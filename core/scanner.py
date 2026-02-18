import os
from datetime import datetime
from typing import Set, List, Dict, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from core.crawler import crawl, extract_forms
from core.reporter import generate_report
from checks import exposed_paths, cookies, comments, base64_decode, sqli, ssti, js_analysis
import checks.ai_overview as ai_overview
from ui.banner import show_banner
from utils.http import safe_get

TABLE_WIDTH = 100


@dataclass
class ScanContext:
    base_url: str
    urls: Set[str] = field(default_factory=set)
    forms: List[Dict] = field(default_factory=list)
    scripts: Set[str] = field(default_factory=set)
    findings: List[str] = field(default_factory=list)
    cookies_data: List[Dict] = field(default_factory=list)


console = Console()


def build_site_tree(urls: set, base_url: str, scripts: set = None) -> Tree:
    parsed_base = urlparse(base_url)
    root_name = f"🌐 {parsed_base.netloc}"
    tree = Tree(f"[bold spring_green1]{root_name}[/]")
    
    all_urls = set(urls)
    if scripts:
        all_urls.update(scripts)
    
    paths = {}
    for url in sorted(all_urls):
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != parsed_base.netloc:
            continue
        path = parsed.path.strip('/') or 'index'
        
        segments = path.split('/')
        current = paths
        for segment in segments:
            if segment not in current:
                current[segment] = {}
            current = current[segment]
    
    def add_branches(parent_tree, path_dict, prefix=""):
        for name, children in sorted(path_dict.items()):
            if '.' in name:
                ext = name.split('.')[-1].lower()
                icons = {
                    'html': '📄',
                    'css': '🎨',
                    'js': '⚡',
                    'json': '📋',
                    'php': '🐘',
                    'py': '🐍',
                    'txt': '📝',
                    'xml': '📰',
                    'png': '🖼️',
                    'jpg': '🖼️',
                    'svg': '🖼️',
                }
                icon = icons.get(ext, '📁')
            else:
                icon = '📂'
            
            branch = parent_tree.add(f"{icon} [white]{name}[/]")
            if children:
                add_branches(branch, children)
    
    add_branches(tree, paths)
    return tree



def _run_sqli_only_scan(url: str, max_depth: int = 2):
    from rich.prompt import Prompt

    scan_start = datetime.now()
    ctx = ScanContext(url)

    console.print(Panel(
        f"[bold cyan]Target:[/] {url}\n"
        f"[bold cyan]Started:[/] {scan_start.strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold green]🔍 SQL Injection Scan[/]",
        border_style="green",
        width=TABLE_WIDTH,
        title_align="center"
    ))
    console.print()

    with console.status("[bold cyan]Checking for SQL Injections...[/]", spinner="dots"):
        try:
            direct_resp, direct_err = safe_get(url)
            if direct_resp and not direct_err:
                direct_forms = extract_forms(direct_resp.text, url)
                if direct_forms:
                    ctx.forms.extend(direct_forms)
                ctx.urls.add(url)
        except Exception:
            pass

        try:
            crawl_result = crawl(url, max_depth=max_depth, max_urls=50, verbose=False)
            ctx.urls.update(crawl_result.urls)
            ctx.forms.extend(crawl_result.forms)
            ctx.scripts = crawl_result.scripts
        except Exception:
            if not ctx.urls:
                ctx.urls = {url}

        try:
            sqli.run(ctx)
        except Exception as e:
            console.print(f"[red]  ✗ SQL Injection check failed: {e}[/]")

    console.print()

    sqli_results = getattr(ctx, 'sqli_results', [])

    if sqli_results:
        table = Table(
            title="[bold red]💉 SQL Injection Results[/]",
            show_header=True,
            header_style="bold cyan",
            border_style="bright_blue",
            show_lines=True,
            width=TABLE_WIDTH,
        )
        table.add_column("Sl No", style="bold white", justify="center", width=6)
        table.add_column("URL", style="cyan", no_wrap=False, overflow="fold")
        table.add_column("Injection", style="yellow", no_wrap=False, overflow="fold")
        table.add_column("Payload", style="red", no_wrap=False, overflow="fold")
        table.add_column("Response", style="green", no_wrap=False, overflow="fold")

        for i, result in enumerate(sqli_results, 1):
            table.add_row(
                str(i),
                result.get("url", "N/A"),
                result.get("injection", "N/A"),
                result.get("payload", "N/A"),
                result.get("response", "N/A"),
            )

        console.print(table)
    else:
        console.print(Panel.fit(
            "[bold green]✅ No SQL Injection vulnerabilities found![/]",
            border_style="green"
        ))

    console.print()

    scan_end = datetime.now()
    duration = (scan_end - scan_start).total_seconds()
    console.print(f"[dim]Scan completed in {duration:.2f} seconds • {len(ctx.urls)} URLs scanned[/]")
    console.print()

    if sqli_results:
        console.print(Panel.fit(
            "Would you like to make me a [bold cyan]report on SQL injection[/] in this site? [bold](1)[/]\n"
            "Or create a [bold cyan]full report[/]? [bold](2)[/]",
            border_style="bright_blue",
        ))

        choice = Prompt.ask(">", choices=["1", "2"], show_choices=False)

        if choice in ("1", "2"):
            console.print()
            with console.status("[bold cyan]Creating reports...[/]", spinner="dots"):
                report_paths = generate_report(
                    target_url=url,
                    findings=ctx.findings,
                    urls_scanned=len(ctx.urls),
                    scan_start=scan_start
                )

            json_path = report_paths.get('json', '')
            html_path = report_paths.get('html', '')
            json_abs = os.path.abspath(json_path) if json_path else ''
            html_abs = os.path.abspath(html_path) if html_path else ''
            console.print(f"  ✓ JSON report: [link=file://{json_abs}][cyan]{json_path}[/][/link]")
            console.print(f"  ✓ HTML report: [link=file://{html_abs}][cyan]{html_path}[/][/link]")
            console.print()


def run_scan(url: str, enable_crawl: bool = True, max_depth: int = 2, vuln_filter: list = None):
    if vuln_filter == ["sqli"]:
        return _run_sqli_only_scan(url, max_depth)

    scan_start = datetime.now()
    ctx = ScanContext(url)

    console.print(Panel(
        f"[bold spring_green1]Target:[/] {url}\n"
        f"[bold spring_green1]Started:[/] {scan_start.strftime('%d/%m/%Y at %I:%M:%S %p')}",
        title="[bold spring_green1]Scan Started[/]",
        border_style="spring_green1",
        width=TABLE_WIDTH,
        title_align="center"
    ))
    console.print()

    if enable_crawl:
        console.print("[bold spring_green1]Phase 1: Crawling[/]")
        with console.status("[bold white]Discovering pages...[/]\n", spinner="material") as status:
            try:
                crawl_result = crawl(url, max_depth=max_depth, max_urls=50, verbose=False)
                ctx.urls = crawl_result.urls
                ctx.forms = crawl_result.forms
                ctx.scripts = crawl_result.scripts
            except Exception as e:
                console.print(f"[yellow]  ⚠ Crawl failed: {e}[/]")
                ctx.urls = {url}
        
        console.print(f"✓ Discovered [spring_green1]{len(ctx.urls)} URLs[/], [spring_green1]{len(ctx.forms)} forms[/]\n")
        
        tree = build_site_tree(ctx.urls, url, ctx.scripts if hasattr(ctx, 'scripts') else None)
        console.print(tree)
        
        console.print()
    else:
        ctx.urls = {url}

    console.print("[bold yellow]Phase 2: Security Checks[/]")
    console.print()
    
    all_check_keys = ["exposed_paths", "cookies", "comments", "base64_decode", "sqli", "ssti", "js_analysis"]
    if vuln_filter is not None:
        run_keys = [k for k in all_check_keys if k in vuln_filter]
        if not run_keys:
            console.print("[yellow]  ⚠ No matching checks. Running all.[/]")
            run_keys = all_check_keys
    else:
        run_keys = all_check_keys
    
    if "exposed_paths" in run_keys:
        console.print("[bold cyan]  🔓 Checking for Exposed Paths[/]")
        try:
            exposed_paths.run(ctx)
        except Exception as e:
            console.print(f"[red]    ✗ Failed: {e}[/]")
        
        ep_results = getattr(ctx, 'exposed_path_results', [])
        if ep_results:
            ep_sorted = sorted(ep_results, key=lambda r: r['status'])
            ep_table = Table(
                show_header=True,
                header_style="bold cyan",
                border_style="bright_blue",
                show_lines=True,
                width=TABLE_WIDTH,
            )
            ep_table.add_column("Sl No", style="bold white", justify="center", width=6)
            ep_table.add_column("Route", style="cyan", no_wrap=False, overflow="fold")
            ep_table.add_column("Status", justify="center", width=8)
            ep_table.add_column("Risk", style="yellow", no_wrap=False, overflow="fold")

            for i, result in enumerate(ep_sorted, 1):
                status = result['status']
                if status == 200:
                    status_str = f"[bold red]{status}[/]"
                elif status in (301, 302, 307, 308):
                    status_str = f"[yellow]{status}[/]"
                elif status == 403:
                    status_str = f"[dim white]{status}[/]"
                else:
                    status_str = str(status)
                ep_table.add_row(str(i), result.get('route', 'N/A'), status_str, result.get('risk', 'N/A'))
            console.print(ep_table)
        else:
            console.print("[green]    ✓ No exposed paths found[/]")
        console.print()
    
    if "cookies" in run_keys:
        console.print("[bold cyan]  🍪 Checking Cookies[/]")
        try:
            cookies.run(ctx)
        except Exception as e:
            console.print(f"[red]    ✗ Failed: {e}[/]")
        
        cookie_results = getattr(ctx, 'cookie_results', [])
        if cookie_results:
            console.print(f"  [yellow]{len(cookie_results)} cookie(s) found[/]")
            for idx, ck in enumerate(cookie_results, 1):
                ck_table = Table(
                    title=f"[bold yellow]Cookie {idx}[/]",
                    show_header=True,
                    header_style="bold cyan",
                    border_style="bright_blue",
                    show_lines=True,
                    width=TABLE_WIDTH,
                )
                ck_table.add_column("Field", style="bold white", width=20)
                ck_table.add_column("Value", style="white", no_wrap=False, overflow="fold")
                ck_table.add_row("Name", ck.get("name", "—"))
                ck_table.add_row("Value", ck.get("value", "—"))
                ck_table.add_row("Domain", ck.get("domain", "—"))
                ck_table.add_row("Path", ck.get("path", "—"))
                ck_table.add_row("HttpOnly", ck.get("httponly", "—"))
                ck_table.add_row("Secure", ck.get("secure", "—"))
                console.print(ck_table)
        else:
            console.print("[green]    ✓ No cookies found[/]")
        console.print()
    
    if "comments" in run_keys:
        console.print("[bold cyan]  📝 Searching for Exposed Comments[/]")
        try:
            with console.status("[dim]    Scanning pages...[/]", spinner="dots"):
                comments.run(ctx)
        except Exception as e:
            console.print(f"[red]    ✗ Failed: {e}[/]")
        
        comment_results = getattr(ctx, 'comment_results', [])
        if comment_results:
            ct = Table(
                show_header=True,
                header_style="bold cyan",
                border_style="bright_blue",
                show_lines=True,
                width=TABLE_WIDTH,
            )
            ct.add_column("Sl No", style="bold white", justify="center", width=6)
            ct.add_column("Comment", style="white", no_wrap=False, overflow="fold")
            ct.add_column("File", style="cyan", no_wrap=False, overflow="fold")
            ct.add_column("Line No", justify="center", width=8)
            for i, r in enumerate(comment_results, 1):
                ct.add_row(str(i), r.get("comment", ""), r.get("file", ""), str(r.get("line", "—")))
            console.print(ct)
        else:
            console.print("[green]    ✓ No exposed comments found[/]")
        console.print()
    
    if "base64_decode" in run_keys:
        console.print("[bold cyan]  🔐 Checking Suspicious Code[/]")
        pre_count = len(ctx.findings)
        try:
            with console.status("[dim]    Analyzing source code...[/]", spinner="dots"):
                base64_decode.run(ctx)
        except Exception as e:
            console.print(f"[red]    ✗ Failed: {e}[/]")
        
        new_findings = [f for f in ctx.findings[pre_count:] if 'Base64' in f]
        if new_findings:
            for i, f in enumerate(new_findings, 1):
                if 'Base64 found in' in f:
                    try:
                        parts = f.split('→')
                        location_part = parts[0] if parts else ""
                        decoded_part = parts[1] if len(parts) > 1 else ""
                        page = location_part.split('in ')[1].split(' (')[0] if 'in ' in location_part else 'unknown'
                        encoded = location_part.split('"')[1] if '"' in location_part else ''
                        decoded = decoded_part.split('"')[1] if '"' in decoded_part else decoded_part.strip()
                        console.print(f"     [dim]-[/] {i}. Base64 string found ([cyan]{page}[/])")
                        console.print(f'              [dim]*[/] [yellow]"{encoded}"[/]')
                        console.print(f'              [dim]*[/] Decoded: [bold green]"{decoded}"[/]')
                    except:
                        console.print(f"     [dim]-[/] {i}. {f}")
        else:
            console.print("[green]    ✓ No suspicious code found[/]")
        console.print()
    
    if "sqli" in run_keys:
        console.print("[bold cyan]  💉 Checking SQL Injection[/]")
        try:
            with console.status("[dim]    Testing payloads...[/]", spinner="dots"):
                sqli.run(ctx)
        except Exception as e:
            console.print(f"[red]    ✗ Failed: {e}[/]")
        
        sqli_results = getattr(ctx, 'sqli_results', [])
        if sqli_results:
            st = Table(
                show_header=True,
                header_style="bold cyan",
                border_style="bright_blue",
                show_lines=True,
                width=TABLE_WIDTH,
            )
            st.add_column("Sl No", style="bold white", justify="center", width=6)
            st.add_column("URL", style="cyan", no_wrap=False, overflow="fold")
            st.add_column("Payload", style="red", no_wrap=False, overflow="fold")
            st.add_column("Info", style="yellow", no_wrap=False, overflow="fold")
            for i, r in enumerate(sqli_results, 1):
                info = r.get("response", r.get("injection", "N/A"))
                st.add_row(str(i), r.get("url", "N/A"), r.get("payload", "N/A"), info)
            console.print(st)
        else:
            console.print("[green]    ✓ No SQL injection vulnerabilities found[/]")
        console.print()
    
    if "ssti" in run_keys:
        console.print("[bold cyan]  🎯 Checking SSTI[/]")
        try:
            with console.status("[dim]    Testing template payloads...[/]", spinner="dots"):
                ssti.run(ctx)
        except Exception as e:
            console.print(f"[red]    ✗ Failed: {e}[/]")
        
        ssti_results = getattr(ctx, 'ssti_results', [])
        if ssti_results:
            tt = Table(
                show_header=True,
                header_style="bold cyan",
                border_style="bright_blue",
                show_lines=True,
                width=TABLE_WIDTH,
            )
            tt.add_column("Sl No", style="bold white", justify="center", width=6)
            tt.add_column("URL", style="cyan", no_wrap=False, overflow="fold")
            tt.add_column("Payload", style="red", no_wrap=False, overflow="fold")
            tt.add_column("Info", style="yellow", no_wrap=False, overflow="fold")
            for i, r in enumerate(ssti_results, 1):
                tt.add_row(str(i), r.get("url", "N/A"), r.get("payload", "N/A"), r.get("info", "N/A"))
            console.print(tt)
        else:
            console.print("[green]    ✓ No SSTI vulnerabilities found[/]")
        console.print()
    
    if "js_analysis" in run_keys:
        console.print("[bold cyan]  ⚡ Checking JavaScript & localStorage[/]")
        pre_count = len(ctx.findings)
        try:
            with console.status("[dim]    Analyzing scripts...[/]", spinner="dots"):
                js_analysis.run(ctx)
        except Exception as e:
            console.print(f"[red]    ✗ Failed: {e}[/]")
        
        new_js = [f for f in ctx.findings[pre_count:] if 'JavaScript' in f or 'API endpoint' in f or 'secret' in f.lower()]
        if new_js:
            for i, f in enumerate(new_js, 1):
                console.print(f"     [dim]-[/] {i}. [yellow]{f}[/]")
        else:
            console.print("[green]    ✓ No suspicious JavaScript found[/]")
        console.print()
    
    console.print("[green]  ✓ All security checks completed[/]")
    console.print()

    other_findings = []
    for f in ctx.findings:
        if not any(kw in f for kw in ['HTML comment', 'Base64', 'Exposed path', 'Cookie', 'SQL', 'SSTI', 'Template', 'JavaScript', 'API endpoint', 'secret', 'Content of']):
            other_findings.append(f)
    
    if other_findings:
        console.print("[bold yellow]Phase 3: Other Findings[/]")
        for i, f in enumerate(other_findings, 1):
            console.print(f"     [dim]-[/] {i}. {f}")
        console.print()

    console.print("[bold yellow]Phase 4: AI Overview[/]")
    try:
        ai_overview.run(ctx)
    except Exception as e:
        console.print(f"[yellow]Skipping AI analysis: {e}[/]")
    console.print()

    console.print("[bold yellow]Phase 5: Generating Report[/]")
    with console.status("[bold cyan]Creating reports...[/]", spinner="dots"):
        report_paths = generate_report(
            target_url=url,
            findings=ctx.findings,
            urls_scanned=len(ctx.urls),
            scan_start=scan_start
        )
    
    json_path = report_paths.get('json', '')
    html_path = report_paths.get('html', '')
    json_abs = os.path.abspath(json_path) if json_path else ''
    html_abs = os.path.abspath(html_path) if html_path else ''
    
    console.print(f"  ✓ JSON report: [link=file://{json_abs}][cyan]{json_path}[/][/link]")
    console.print(f"  ✓ HTML report: [link=file://{html_abs}][cyan]{html_path}[/][/link]")
    console.print()
    
    scan_end = datetime.now()
    duration = (scan_end - scan_start).total_seconds()
    
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column(style="bold")
    summary_table.add_column()
    summary_table.add_row("Duration", f"{duration:.2f} seconds")
    summary_table.add_row("URLs Scanned", str(len(ctx.urls)))
    summary_table.add_row("Findings", str(len(ctx.findings)))
    
    console.print(Panel(
        summary_table,
        title="[bold green]✅ Scan Complete[/]",
        border_style="green",
        width=TABLE_WIDTH,
        title_align="center"
    ))
