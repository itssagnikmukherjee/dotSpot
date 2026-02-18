import requests
from rich.console import Console
from rich.table import Table

console = Console()

TABLE_WIDTH = 100


def run(ctx):
    if not hasattr(ctx, 'cookie_results'):
        ctx.cookie_results = []

    try:
        r = requests.get(ctx.base_url, timeout=5, verify=False)
    except Exception:
        return

    if not r.cookies:
        return

    for c in r.cookies:
        httponly = "Yes" if c.has_nonstandard_attr("HttpOnly") else "No"
        secure = "Yes" if c.secure else "No"
        domain = c.domain or "—"
        path = c.path or "/"
        expires = c.expires or "—"

        ctx.cookie_results.append({
            "name": c.name,
            "value": c.value or "",
            "domain": domain,
            "path": path,
            "httponly": httponly,
            "secure": secure,
            "expires": expires,
        })

        issues = []
        if httponly == "No":
            issues.append("missing HttpOnly")
        if secure == "No":
            issues.append("missing Secure")
        if expires == "—":
            issues.append("no expiration date")
        if issues:
            ctx.findings.append(f"Cookie issue ({c.name}): {', '.join(issues)}")
