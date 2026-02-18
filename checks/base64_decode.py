
import re
import base64
from typing import List, Tuple, Optional
from rich.console import Console

from utils.http import safe_get

console = Console()

MIN_BASE64_LENGTH = 20
MAX_FINDINGS = 10

FALSE_POSITIVES = [
    'data:image',
    'data:audio',
    'data:video',
    'data:font',
    'data:application',
    'googleapis.com',
    'gstatic.com',
    'jquery',
    'bootstrap',
    'sourceMappingURL'
]


def is_valid_base64(s: str) -> bool:
    if len(s) < MIN_BASE64_LENGTH:
        return False
    
    if not re.match(r'^[A-Za-z0-9+/=]+$', s):
        return False
    
    if len(s) % 4 not in [0, 2, 3]:
        padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 != 0 else s
        if len(padded) % 4 != 0:
            return False
    
    return True


def decode_base64(s: str) -> Optional[str]:
    try:
        padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 != 0 else s
        decoded_bytes = base64.b64decode(padded)
        
        try:
            decoded = decoded_bytes.decode('utf-8')
            if all(c.isprintable() or c in '\n\r\t' for c in decoded):
                return decoded
        except UnicodeDecodeError:
            try:
                decoded = decoded_bytes.decode('latin-1')
                if all(c.isprintable() or c in '\n\r\t' for c in decoded):
                    return decoded
            except:
                pass
    except Exception:
        pass
    
    return None


def categorize_decoded(decoded: str) -> Tuple[str, str]:
    decoded_lower = decoded.lower()
    
    if any(p in decoded_lower for p in ['password', 'passwd', 'secret', 'api_key', 'apikey', 'token', 'auth']):
        return 'credential', 'critical'
    
    if re.search(r'flag\{|ctf\{|picoCTF\{', decoded, re.IGNORECASE):
        return 'flag', 'critical'
    
    if decoded.strip().startswith('{') and decoded.strip().endswith('}'):
        return 'json', 'high'
    
    if 'http://' in decoded or 'https://' in decoded:
        return 'url', 'medium'
    
    if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', decoded):
        return 'email', 'medium'
    
    if re.search(r'^(/|[A-Za-z]:\\)', decoded) or '/' in decoded:
        return 'path', 'low'
    
    return 'text', 'info'


def is_interesting(decoded: str) -> bool:
    if len(decoded) < 5:
        return False
    
    if '\x00' in decoded:
        return False
    
    decoded_lower = decoded.lower()
    skip_patterns = [
        'lorem ipsum',
        'copyright',
        'license',
        'all rights reserved'
    ]
    if any(p in decoded_lower for p in skip_patterns):
        return False
    
    alpha_ratio = sum(c.isalpha() for c in decoded) / len(decoded)
    if alpha_ratio < 0.3:
        return False
    
    return True


def find_base64_strings(html: str) -> List[Tuple[str, str, str, str]]:
    findings = []
    
    pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(pattern, html)
    
    for match in matches:
        if any(fp in match for fp in FALSE_POSITIVES):
            continue
        
        context_start = html.find(match)
        if context_start > 0:
            context = html[max(0, context_start - 50):context_start]
            if any(fp in context for fp in FALSE_POSITIVES):
                continue
        
        if is_valid_base64(match):
            decoded = decode_base64(match)
            if decoded and is_interesting(decoded):
                category, severity = categorize_decoded(decoded)
                findings.append((match, decoded, category, severity))
    
    seen = set()
    unique_findings = []
    for f in findings:
        if f[1] not in seen:
            seen.add(f[1])
            unique_findings.append(f)
    
    return unique_findings[:MAX_FINDINGS]


def run(ctx):
    urls_to_scan = list(ctx.urls) if hasattr(ctx, 'urls') and ctx.urls else [ctx.base_url]
    
    all_findings = []
    
    for url in urls_to_scan:
        response, error = safe_get(url)
        if error or not response:
            continue
        
        page_findings = find_base64_strings(response.text)
        
        for original, decoded, category, severity in page_findings:
            if not any(decoded == f[1] for f in all_findings):
                all_findings.append((original, decoded, category, severity, url))
    
    if not all_findings:
        return
    
    for original, decoded, category, severity, source_url in all_findings[:MAX_FINDINGS]:
        page_name = source_url.split('/')[-1] or 'index'
        display_encoded = original if len(original) <= 50 else original[:50] + "..."
        finding = f"Base64 found in {page_name} ({category}): \"{display_encoded}\" → Decoded: \"{decoded}\""
        ctx.findings.append(finding)
    
    if len(all_findings) > MAX_FINDINGS:
        remaining = len(all_findings) - MAX_FINDINGS
        ctx.findings.append(f"Base64: {remaining} additional encoded strings not shown")
