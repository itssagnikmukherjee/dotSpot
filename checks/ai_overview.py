import os
import json
import re
from typing import Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

console = Console()

GROQ_API_URL = os.environ.get("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "llama-3.3-70b-versatile")

TABLE_WIDTH = 100

def get_groq_api_key() -> Optional[str]:
    return os.environ.get("GROQ_API_KEY")


def analyze_with_groq(scan_data: Dict, api_key: str) -> str:
    try:
        from groq import Groq, APIError
    except ImportError:
        console.print("Groq SDK not installed")
        return ""
    
    client = Groq(api_key=api_key)
    
    findings_text = json.dumps(scan_data.get("findings", []), indent=2)

    prompt_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'prompt.txt')
    prompt = open(prompt_path, "r").read()

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": findings_text}
            ],
            model=DEFAULT_MODEL,
            temperature=0.3,
            max_tokens=2000
        )
        
        return chat_completion.choices[0].message.content
    
    except APIError as e:
        console.print("Groq API Error")
        console.print(f"Type: {type(e).__name__}")
        console.print(f"Message: {str(e)}")
        if "model" in str(e).lower():
            console.print(f"Hint: The model '{DEFAULT_MODEL}' might be invalid or deprecated.")
        return ""
    except Exception as e:
        console.print(f"Unexpected error during AI analysis: {e}")
        return ""


def analyze_scan_report(json_path: str, api_key: Optional[str] = None) -> None:
    key = api_key or get_groq_api_key()
    if not key:
        console.print("API KEY NOT FOUND")
        return

    try:
        with open(json_path, 'r') as f:
            scan_data = json.load(f)
    except FileNotFoundError:
        console.print(f"File not found: {json_path}")
        return
    except json.JSONDecodeError:
        console.print(f"Invalid JSON file: {json_path}")
        return
    
    console.print(Panel.fit(
        f"[bold cyan]Analyzing:[/] {json_path}\n"
        f"[bold cyan]Model:[/] {DEFAULT_MODEL}",
        title="[bold green]🤖 AI Analysis[/]",
        border_style="green"
    ))
    
    with console.status("[bold cyan]Analyzing with Groq AI...[/]", spinner="dots"):
        analysis = analyze_with_groq(scan_data, key)
    
    if analysis:
        console.print()
        console.print(Panel(
            Markdown(analysis),
            title="[bold green]🔍 Security Analysis[/]",
            border_style="cyan",
            padding=(1, 2)
        ))


def _parse_ai_table(analysis: str) -> list:
    rows = []
    for line in analysis.strip().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('---'):
            continue
        if 'vulnerability' in line.lower() and 'info' in line.lower() and 'fix' in line.lower():
            continue
        parts = [p.strip() for p in line.split('|')]
        parts = [p for p in parts if p]
        if len(parts) >= 3:
            rows.append((parts[0], parts[1], parts[2]))
        elif len(parts) == 2:
            rows.append((parts[0], parts[1], "—"))
        elif len(parts) == 1 and line.startswith('-'):
            cleaned = line.lstrip('- ').strip()
            if ':' in cleaned:
                vuln, info = cleaned.split(':', 1)
                rows.append((vuln.strip(), info.strip(), "—"))
    return rows


def run(ctx):
    key = get_groq_api_key()
    if not key:
        return
    
    scan_data = {
        "target_url": ctx.base_url,
        "findings": [{"description": f} for f in ctx.findings],
        "summary": {"total": len(ctx.findings)}
    }
    
    with console.status("[bold cyan]Getting AI insights...[/]", spinner="dots"):
        analysis = analyze_with_groq(scan_data, key)
    
    if analysis:
        rows = _parse_ai_table(analysis)
        if rows:
            ai_table = Table(
                title="[bold green]🤖 AI Insights[/]",
                show_header=True,
                header_style="bold cyan",
                border_style="cyan",
                show_lines=True,
                width=TABLE_WIDTH,
            )
            ai_table.add_column("Vulnerability", style="red", ratio=1, no_wrap=False, overflow="fold")
            ai_table.add_column("Info", style="white", ratio=2, no_wrap=False, overflow="fold")
            ai_table.add_column("Potential Fix", style="green", ratio=2, no_wrap=False, overflow="fold")

            for vuln, info, fix in rows:
                ai_table.add_row(vuln, info, fix)
            console.print(ai_table)
        else:
            console.print(Panel(
                Markdown(analysis),
                title="[bold green]🤖 AI Insights[/]",
                border_style="cyan"
            ))
