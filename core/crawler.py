import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, List, Dict, Optional, Tuple
from collections import deque
from dataclasses import dataclass, field

from utils.http import safe_get, normalize_url
from rich.console import Console

console = Console()


@dataclass
class CrawlResult:
    urls: Set[str] = field(default_factory=set)
    forms: List[Dict] = field(default_factory=list)
    scripts: Set[str] = field(default_factory=set)
    parameters: Dict[str, Set[str]] = field(default_factory=dict)


@dataclass
class Form:
    action: str
    method: str
    inputs: List[Dict[str, str]]


def extract_links(html: str, base_url: str) -> Set[str]:
    links = set()
    
    href_pattern = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    for match in href_pattern.finditer(html):
        url = match.group(1)
        if not url.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
            absolute_url = urljoin(base_url, url)
            links.add(absolute_url)
    
    return links


def extract_scripts(html: str, base_url: str) -> Set[str]:
    scripts = set()
    
    src_pattern = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    for match in src_pattern.finditer(html):
        src = match.group(1)
        absolute_url = urljoin(base_url, src)
        scripts.add(absolute_url)
    
    return scripts


def extract_forms(html: str, base_url: str) -> List[Dict]:
    forms = []
    
    form_pattern = re.compile(
        r'<form[^>]*>(.*?)</form>',
        re.IGNORECASE | re.DOTALL
    )
    
    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        form_content = form_match.group(1)
        
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action = urljoin(base_url, action_match.group(1)) if action_match else base_url
        
        method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else 'GET'
        
        inputs = []
        input_pattern = re.compile(
            r'<input[^>]*>|<textarea[^>]*>.*?</textarea>|<select[^>]*>.*?</select>',
            re.IGNORECASE | re.DOTALL
        )
        
        for input_match in input_pattern.finditer(form_content):
            input_html = input_match.group(0)
            
            name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            type_match = re.search(r'type\s*=\s*["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            
            if name_match:
                inputs.append({
                    'name': name_match.group(1),
                    'type': type_match.group(1) if type_match else 'text',
                    'value': value_match.group(1) if value_match else ''
                })
        
        forms.append({
            'action': action,
            'method': method,
            'inputs': inputs
        })
    
    return forms


def extract_parameters(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {k: v[0] if v else '' for k, v in params.items()}


def is_same_domain(url: str, base_domain: str) -> bool:
    parsed = urlparse(url)
    return parsed.netloc == base_domain or parsed.netloc.endswith('.' + base_domain)


def should_crawl(url: str) -> bool:
    skip_extensions = (
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz',
        '.mp3', '.mp4', '.avi', '.mov', '.webm', '.woff', '.woff2', '.ttf', '.eot'
    )
    
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    return not any(path.endswith(ext) for ext in skip_extensions)


def crawl(
    start_url: str,
    max_depth: int = 3,
    max_urls: int = 100,
    verbose: bool = True
) -> CrawlResult:
    start_url = normalize_url(start_url)
    base_domain = urlparse(start_url).netloc
    
    result = CrawlResult()
    visited: Set[str] = set()
    queue: deque = deque([(start_url, 0)])
    
    while queue and len(visited) < max_urls:
        current_url, depth = queue.popleft()
        
        if current_url in visited:
            continue
        
        if depth > max_depth:
            continue
        
        if not is_same_domain(current_url, base_domain):
            continue
        
        if not should_crawl(current_url):
            continue
        
        visited.add(current_url)
        result.urls.add(current_url)
        
        if verbose:
            console.print(f"  [dim]Crawling:[/] {current_url[:70]}...")
        
        response, error = safe_get(current_url)
        if error or not response:
            continue
        
        html = response.text
        
        links = extract_links(html, current_url)
        for link in links:
            if link not in visited:
                queue.append((link, depth + 1))
        
        scripts = extract_scripts(html, current_url)
        result.scripts.update(scripts)
        
        forms = extract_forms(html, current_url)
        result.forms.extend(forms)
        
        params = extract_parameters(current_url)
        if params:
            result.parameters[current_url] = set(params.keys())
    
    return result


def quick_crawl(url: str, depth: int = 2) -> Set[str]:
    result = crawl(url, max_depth=depth, max_urls=50, verbose=False)
    return result.urls
