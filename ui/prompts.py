from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

VULN_TYPE_MAP = {
    "1": {
        "label": "Poor Code (server side)",
        "checks": ["comments", "base64_decode"],
    },
    "2": {
        "label": "Poor Code (Client side)",
        "checks": ["js_analysis"],
    },
    "3": {
        "label": "Exposed Paths",
        "checks": ["exposed_paths"],
    },
    "4": {
        "label": "Cookies & Local Storage",
        "checks": ["cookies"],
    },
    "5": {
        "label": "SQL Injection",
        "checks": ["sqli"],
    },
    "6": {
        "label": "XSS",
        "checks": [],
    },
    "7": {
        "label": "SSTI",
        "checks": ["ssti"],
    },
}


def ask_mode() -> str:
    console.print()
    # console.print(Panel(
    #     f"[bold cyan]Target:[/] {url}\n"
    #     f"[bold cyan]Started:[/] {scan_start.strftime('%Y-%m-%d %H:%M:%S')}",
    #     title="[bold green]🔍 Scan Started[/]",
    #     border_style="green",
    #     width=TABLE_WIDTH,
    #     title_align="center"
    # ))
    console.print(Panel(
        "\nHi I am [spring_green1]dot[/] and I will help you to [spring_green1]spot[/], "
        "before we proceed tell me something !\nwhat would you  like to do ?\n\n"
        "  [spring_green1][bold]1. Check for vulnerabilities\n[/]"
        "  [cyan bold]2. Find flag\n [/]",
        border_style="white",
        width=100,
        title_align="center"
    ))

    while True:
        choice = Prompt.ask(">", choices=["1", "2"], show_choices=True, default="1")
        if choice in ("1", "2"):
            return choice


def ask_vuln_guess() -> bool:
    console.print()
    console.print(Panel(
        "\nGreat now to [spring_green1]speed up the entire process[/] just another question...\n"
        "Do you know or do you have any guesses about [spring_green1]what the vulnerability can be ?[/]\n",
        border_style="white",
        width=100,
        title_align="center"
    ))

    answer = Prompt.ask(">", choices=["y", "N"], default="N", show_choices=True)
    return answer.strip().lower() in ("y", "yes")


def ask_vuln_type() -> str:
    console.print()
    console.print(Panel(
        "\n[spring_green1]Which vulnerability category do you want to analyze?[/]\n\n"
        "  [bold]1.[/] Server-Side Code Issues (e.g., exposed API keys, backup files, sensitive comments)\n"
        "  [bold]2.[/] Client-Side Code Issues (e.g., hardcoded tokens, hidden endpoints in JS)\n"
        "  [bold]3.[/] Exposed Directories & Paths (e.g., /admin, /uploads/, .git/ accessible)\n"
        "  [bold]4.[/] Cookies & Browser Storage (e.g., insecure session cookies, JWT in localStorage)\n"
        "  [bold]5.[/] SQL Injection (e.g., login bypass, authentication bypass)\n"
        "  [bold]6.[/] Cross-Site Scripting (XSS) (e.g., script tags in input fields)\n"
        "  [bold]7.[/] Server-Side Template Injection (SSTI) (e.g., expression evaluation)\n",
        border_style="white",
        width=100,
        title_align="center"
    ))

    while True:
        choice = Prompt.ask(">", choices=["1", "2", "3", "4", "5", "6", "7"], show_choices=False)
        if choice in VULN_TYPE_MAP:
            return choice


def get_checks_for_vuln_type(vuln_choice: str) -> list:
    entry = VULN_TYPE_MAP.get(vuln_choice, {})
    return entry.get("checks", [])


def run_interactive_prompts() -> dict:
    mode = ask_mode()

    if mode == "2":
        return {"mode": "flag", "vuln_filter": None}

    has_guess = ask_vuln_guess()

    if has_guess:
        vuln_choice = ask_vuln_type()
        checks = get_checks_for_vuln_type(vuln_choice)

        if not checks:
            return {"mode": "vulnerabilities", "vuln_filter": None}

        return {"mode": "vulnerabilities", "vuln_filter": checks}

    return {"mode": "vulnerabilities", "vuln_filter": None}
