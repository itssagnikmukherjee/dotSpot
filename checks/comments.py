import re
from typing import List, Tuple
from rich.console import Console

from utils.http import safe_get

console = Console()

MAX_COMMENT_LENGTH = 200
MAX_COMMENTS_TO_REPORT = 10


def clean_comment(comment: str) -> str:
    cleaned = re.sub(r'\s+', ' ', comment.strip())
    if len(cleaned) > MAX_COMMENT_LENGTH:
        cleaned = cleaned[:MAX_COMMENT_LENGTH] + "..."
    return cleaned


def find_comment_position(html: str, raw_comment: str) -> Tuple[int, int]:
    marker = f"<!--{raw_comment}-->"
    pos = html.find(marker)
    
    if pos == -1:
        pos = html.find(f"<!--{raw_comment}")
    
    if pos >= 0:
        before = html[:pos]
        line_number = before.count('\n') + 1
        last_newline = before.rfind('\n')
        column = (pos + 1) if last_newline == -1 else (pos - last_newline)
        return line_number, column
    
    return 0, 0


def categorize_comment(comment: str) -> Tuple[str, str]:
    comment_lower = comment.lower()
    
    if any(p in comment_lower for p in ['password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 'token']):
        return 'credential', 'high'
    
    if any(p in comment_lower for p in ['todo', 'fixme', 'hack', 'xxx', 'bug']):
        return 'todo', 'medium'
    
    if any(p in comment_lower for p in ['debug', 'test', 'dev', 'staging']):
        return 'debug', 'medium'
    
    if any(p in comment_lower for p in ['version', 'v1', 'v2', 'build']):
        return 'version', 'low'
    
    if any(p in comment_lower for p in ['author', 'created', 'modified', 'copyright']):
        return 'metadata', 'info'
    
    if re.search(r'\b(?:localhost|127\.0\.0\.1|192\.168\.|10\.)', comment_lower):
        return 'internal_url', 'medium'
    
    if re.search(r'function|var |let |const |class |def |import ', comment):
        return 'code', 'low'
    
    return 'general', 'info'


def run(ctx):
    urls_to_scan = list(ctx.urls) if hasattr(ctx, 'urls') and ctx.urls else [ctx.base_url]
    
    if not hasattr(ctx, 'comment_results'):
        ctx.comment_results = []
    
    all_comments = []
    
    for url in urls_to_scan:
        response, error = safe_get(url)
        if error or not response:
            continue
        
        page_name = url.split('/')[-1] or 'index.html'
        html_content = response.text
    
        comments = re.findall(r"<!--(.*?)-->", html_content, re.DOTALL)
        
        for comment in comments:
            cleaned = clean_comment(comment)
            if len(cleaned) > 5 and not cleaned.startswith('[if '):
                if not any(cleaned == c[0] for c in all_comments):
                    line, col = find_comment_position(html_content, comment)
                    all_comments.append((cleaned, page_name, line, col))
    
    if not all_comments:
        return
    
    for comment, page, line, col in all_comments[:MAX_COMMENTS_TO_REPORT]:
        category, severity = categorize_comment(comment)
        
        location = f"{line},{col}" if line > 0 else "0,0"
        finding = f"HTML comment in {page} ({location}): \"{comment}\""
        ctx.findings.append(finding)
        
        ctx.comment_results.append({
            "comment": comment,
            "file": page,
            "line": line if line > 0 else "—",
        })
    
    if len(all_comments) > MAX_COMMENTS_TO_REPORT:
        remaining = len(all_comments) - MAX_COMMENTS_TO_REPORT
        ctx.findings.append(f"HTML comments: {remaining} additional comments not shown")
