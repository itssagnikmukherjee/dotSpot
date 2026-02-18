import os
from typing import Set, List, Tuple
from rich.console import Console
from rich.text import Text
from rich.live import Live

from utils.http import safe_get

console = Console()

DEFAULT_PATHS = [
    '/admin', '/.env', '/.git/config', '/backup', '/robots.txt',
    '/sitemap.xml', '/config.php', '/wp-admin', '/phpmyadmin',
    '/.htaccess', '/api', '/swagger.json', '/graphql'
]


def load_paths() -> List[str]:
    paths_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'paths.txt')
    
    try:
        with open(paths_file, 'r') as f:
            paths = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    paths.append(line)
            return paths if paths else DEFAULT_PATHS
    except FileNotFoundError:
        console.print("[yellow]    Warning: paths.txt not found, using defaults[/]")
        return DEFAULT_PATHS
    except Exception:
        return DEFAULT_PATHS


def categorize_finding(path: str, status_code: int, content_length: int) -> Tuple[str, str]:
    path_lower = path.lower()
    
    critical_patterns = ['.env', '.git', 'credentials', 'secrets', 'api_key', 'password', '.htpasswd']
    if any(p in path_lower for p in critical_patterns):
        return 'critical', 'Sensitive configuration/secrets file'
    
    high_patterns = ['admin', 'phpmyadmin', 'cpanel', 'backup', 'database', 'dump', '.sql']
    if any(p in path_lower for p in high_patterns):
        return 'high', 'Administrative or database access'
    
    medium_patterns = ['api', 'swagger', 'graphql', 'config', 'debug', 'test']
    if any(p in path_lower for p in medium_patterns):
        return 'medium', 'API or configuration endpoint'
    
    if status_code == 200:
        return 'low', 'Accessible path'
    elif status_code in [301, 302, 307, 308]:
        return 'info', 'Redirect detected'
    elif status_code == 403:
        return 'info', 'Path exists but forbidden'
    
    return 'info', 'Path discovered'


def run(ctx):
    from urllib.parse import urlparse

    if not hasattr(ctx, 'exposed_path_results'):
        ctx.exposed_path_results = []

    paths = load_paths()

    response, error = safe_get(ctx.base_url, allow_redirects=True)
    baseline_length = len(response.text) if response else 0

    parsed_base = urlparse(ctx.base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    base_path = parsed_base.path.rstrip('/')

    url_path_pairs = []
    seen = set()

    for p in paths:
        root_url = f"{origin}{p}"
        if root_url not in seen:
            seen.add(root_url)
            url_path_pairs.append((root_url, p))

        if base_path and base_path != '/':
            relative_url = f"{origin}{base_path}{p}"
            if relative_url not in seen:
                seen.add(relative_url)
                url_path_pairs.append((relative_url, f"{base_path}{p}"))

    total = len(url_path_pairs)
    found_paths: Set[str] = set()

    with Live(console=console, refresh_per_second=10, transient=True) as live:
        for idx, (url, display_path) in enumerate(url_path_pairs, 1):
            progress_text = Text()
            progress_text.append("    Checking: ", style="dim")
            progress_text.append(display_path, style="cyan")
            progress_text.append(f"  ({idx}/{total})", style="dim")
            live.update(progress_text)
            response, error = safe_get(url, allow_redirects=False)

            if error or response is None:
                continue

            status = response.status_code
            content_length = len(response.text)

            is_finding = False

            if status == 200:
                if abs(content_length - baseline_length) > 100:
                    is_finding = True
            elif status in [301, 302, 307, 308]:
                location = response.headers.get('Location', '')
                if 'login' in location.lower() or 'admin' in location.lower():
                    is_finding = True
            elif status == 403:
                is_finding = True

            if is_finding and display_path not in found_paths:
                found_paths.add(display_path)
                severity, desc = categorize_finding(display_path, status, content_length)
                finding = f"Exposed path [{status}] {display_path} ({desc})"
                ctx.findings.append(finding)

                ctx.exposed_path_results.append({
                    "route": display_path,
                    "status": status,
                    "risk": desc,
                })

                important_files = ['robots.txt', '.env', '.git/config', '.htpasswd',
                                 'security.txt', 'sitemap.xml', 'swagger.json',
                                 'config.php', 'config.json', 'config.yml']
                if status == 200 and any(f in display_path for f in important_files):
                    content = response.text.strip()
                    if content and len(content) < 2000:
                        ctx.findings.append(f"Content of {display_path}:\n{content}")

    found_count = len(found_paths)
    console.print(f"  [green]✓[/] Scanned [cyan]{total}[/] paths — [yellow]{found_count}[/] exposed path(s) found")
