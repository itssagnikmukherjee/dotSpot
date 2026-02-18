import re
import json
import os
import subprocess
import tempfile
import shutil
from typing import Set, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from rich.console import Console

from utils.http import safe_get
from utils.patterns import find_secrets

console = Console()

PAYLOADS_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'payloads.json')


def load_secret_patterns() -> Dict:
    try:
        with open(PAYLOADS_PATH, 'r') as f:
            data = json.load(f)
            return data.get('secrets_patterns', {})
    except Exception:
        return {}

        
def execute_js_snippet(js_code: str) -> Optional[str]:
    if not shutil.which('node'):
        return None
        
    if len(js_code) > 10000:
        return None
        
    modified_code = js_code.replace("alert(", "console.log(")
    modified_code = modified_code.replace("window.alert(", "console.log(")
    modified_code = modified_code.replace("prompt(", "console.log(")
    modified_code = modified_code.replace("confirm(", "console.log(")
    
    if "console.log" not in modified_code and "return" not in modified_code:
         pass

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(modified_code)
            temp_path = f.name
            
        result = subprocess.run(
            ['node', temp_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
            
    except Exception as e:
        console.print(f"[red]JS Execution Error: {e}[/]")
        pass
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
                
    return None


def extract_js_urls(html: str, base_url: str) -> Set[str]:
    js_urls = set()
    
    pattern = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
    
    for match in pattern.finditer(html):
        src = match.group(1)
        absolute_url = urljoin(base_url, src)
        js_urls.add(absolute_url)
    
    return js_urls


def extract_inline_js(html: str) -> List[Dict[str, object]]:
    inline_js = []
    
    pattern = re.compile(r'<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
    
    for match in pattern.finditer(html):
        content = match.group(1).strip()
        if content:
            line = html[:match.start()].count('\n') + 1
            inline_js.append({'code': content, 'line': line, 'type': 'script'})
            
    textarea_pattern = re.compile(r'<textarea[^>]*>(.*?)</textarea>', re.IGNORECASE | re.DOTALL)
    for match in textarea_pattern.finditer(html):
        content = match.group(1).strip()
        line = html[:match.start()].count('\n') + 1
        
        if 'javascript:' in content.lower():
             content = re.sub(r'javascript:', '', content, flags=re.IGNORECASE, count=1).strip()
             inline_js.append({'code': content, 'line': line, 'type': 'bookmarklet'})
        elif 'function' in content and '{' in content:
             inline_js.append({'code': content, 'line': line, 'type': 'bookmarklet'})

    js_uri_pattern = re.compile(r'javascript:\s*([^\s"\'<>]+.*?)["\'\<]', re.IGNORECASE)
    
    for match in js_uri_pattern.finditer(html):
        content = match.group(1).strip()
        if len(content) > 10:
            line = html[:match.start()].count('\n') + 1
            inline_js.append({'code': content, 'line': line, 'type': 'bookmarklet'})

    return inline_js


def detect_obfuscation(js_content: str) -> List[str]:
    indicators = []
    
    if re.search(r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)', js_content):
        indicators.append("Packed JS (Dean Edwards / Packer)")
    
    if re.search(r'var\s+_0x[a-f0-9]+', js_content):
        indicators.append("Hex-named variables (often obfuscator.io)")
        
    if re.search(r'\\x[a-f0-9]{2}\\x[a-f0-9]{2}\\x[a-f0-9]{2}', js_content):
        indicators.append("Heavy hex encoding in strings")
        
    if re.search(r'(?:window|document)\[\s*["\']\\x[0-9a-f]{2}', js_content):
        indicators.append("Obfuscated DOM access (hex array access)")
        
    lines = js_content.split('\n')
    avg_line_length = sum(len(line) for line in lines) / len(lines) if lines else 0
    if avg_line_length > 300:
        if len(js_content) > 1000:
             indicators.append(f"Suspiciously long average line length ({int(avg_line_length)} chars) - likely minified/obfuscated")

    if re.search(r'var\s+[a-zA-Z0-9_]+\s*=\s*\[["\']\s*.*?["\']\s*,\s*["\']', js_content) and re.search(r'[a-zA-Z0-9_]+\s*\[\s*0\s*x', js_content):
        indicators.append("String Array checks (obfuscation pattern)")
        
    lower_content = js_content.lower()
    if 'fromcharcode' in lower_content and ('charcodeat' in lower_content or '%' in lower_content):
        indicators.append("Custom character decoding logic (fromCharCode + charCodeAt)")

    return indicators


def find_api_endpoints(js_content: str) -> Set[str]:
    endpoints = set()
    
    patterns = [
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](\\/api\\/[^"\']+)["\']',
        r'["\']([^"\']+/v[0-9]+/[^"\']+)["\']',
        r'baseURL\s*[=:]\s*["\']([^"\']+)["\']',
        r'apiUrl\s*[=:]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
        r'graphql["\']?\s*[=:]\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        for match in re.finditer(pattern, js_content, re.IGNORECASE):
            groups = match.groups()
            endpoint = groups[-1] if groups else match.group(1)
            if endpoint and len(endpoint) > 3:
                endpoint = endpoint.replace('\\/', '/')
                endpoints.add(endpoint)
    
    return endpoints


def find_hardcoded_secrets(js_content: str) -> Dict[str, List[str]]:
    secrets = find_secrets(js_content)
    
    additional_patterns = {
        "api_key_assignment": re.compile(
            r'(?:api[_-]?key|apiKey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            re.IGNORECASE
        ),
        "password_assignment": re.compile(
            r'(?:password|passwd|pwd|secret)\s*[=:]\s*["\']([^"\']{8,})["\']',
            re.IGNORECASE
        ),
        "token_assignment": re.compile(
            r'(?:token|auth|bearer)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            re.IGNORECASE
        ),
        "private_key_var": re.compile(
            r'(?:private[_-]?key|privateKey)\s*[=:]\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        ),
    }
    
    for secret_type, pattern in additional_patterns.items():
        matches = pattern.findall(js_content)
        if matches:
            if secret_type not in secrets:
                secrets[secret_type] = []
            secrets[secret_type].extend(matches)
    
    return secrets


def find_debug_info(js_content: str) -> List[str]:
    findings = []
    
    patterns = {
        "console.log with data": re.compile(r'console\.log\s*\([^)]*(?:password|secret|token|key)[^)]*\)', re.IGNORECASE),
        "debugger statement": re.compile(r'\bdebugger\b'),
        "source map reference": re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)'),
        "internal URL": re.compile(r'(?:localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)[:\d]*'),
        "TODO/FIXME with secrets": re.compile(r'(?:TODO|FIXME|HACK).*(?:password|secret|key|token)', re.IGNORECASE),
    }
    
    for finding_type, pattern in patterns.items():
        matches = pattern.findall(js_content)
        if matches:
            findings.append(f"{finding_type}: {matches[0][:100] if matches else ''}")
    
    return findings


def run(ctx):
    response, error = safe_get(ctx.base_url)
    if error or not response:
        return
    
    js_urls = extract_js_urls(response.text, ctx.base_url)
    inline_js = extract_inline_js(response.text)
    
    parsed_base = urlparse(ctx.base_url)
    base_domain = parsed_base.netloc
    
    same_domain_js = {
        url for url in js_urls 
        if urlparse(url).netloc == base_domain or urlparse(url).netloc == ''
    }
    
    total_secrets = {}
    total_endpoints = set()
    total_debug = []
    total_obfuscation = []
    
    for i, js_item in enumerate(inline_js):
        js_code = js_item['code']
        line_num = js_item['line']
        js_type = js_item.get('type', 'script')
        
        secrets = find_hardcoded_secrets(js_code)
        for k, v in secrets.items():
            if k not in total_secrets:
                total_secrets[k] = []
            total_secrets[k].extend(v)
        
        endpoints = find_api_endpoints(js_code)
        total_endpoints.update(endpoints)
        
        debug_info = find_debug_info(js_code)
        total_debug.extend(debug_info)
        
        obf = detect_obfuscation(js_code)
        
        should_execute = False
        if js_type == 'bookmarklet':
            should_execute = True
        elif obf and ("Custom character decoding logic" in str(obf)):
            should_execute = True
        elif js_code.strip().startswith("(function") and "flag" in js_code.lower():
            should_execute = True

        if obf:
            total_obfuscation.append(f"Inline Script (Line {line_num}): {', '.join(obf)}")
            
        if should_execute:
             try:
                 output = execute_js_snippet(js_code)
                 if output:
                      total_obfuscation.append(f"[bold green]Executed JS Output (Line {line_num}): {output}[/]")
             except Exception:
                 pass

    for js_url in list(same_domain_js)[:10]:
        response, error = safe_get(js_url)
        if error or not response:
            continue
        
        js_content = response.text
        
        secrets = find_hardcoded_secrets(js_content)
        for k, v in secrets.items():
            if k not in total_secrets:
                total_secrets[k] = []
            total_secrets[k].extend(v)
        
        endpoints = find_api_endpoints(js_content)
        total_endpoints.update(endpoints)
        
        debug_info = find_debug_info(js_content)
        total_debug.extend(debug_info)
        
        obf = detect_obfuscation(js_content)
        if obf:
            filename = js_url.split('/')[-1]
            total_obfuscation.append(f"{filename}: {', '.join(obf)}")
    
    for secret_type, values in total_secrets.items():
        unique_values = list(set(values))[:3]
        for value in unique_values:
            masked = value[:8] + "..." + value[-4:] if len(value) > 16 else value[:4] + "..."
            ctx.findings.append(
                f"Exposed secret ({secret_type}) in JavaScript: {masked}"
            )
    
    if total_endpoints:
        endpoints_list = list(total_endpoints)[:5]
        ctx.findings.append(
            f"API endpoints discovered in JavaScript: {', '.join(endpoints_list)}"
        )
    
    for debug in total_debug[:5]:
        ctx.findings.append(f"Debug information in JavaScript: {debug}")
        
    for obf in total_obfuscation:
        ctx.findings.append(f"Obfuscated JavaScript detected: {obf}")
