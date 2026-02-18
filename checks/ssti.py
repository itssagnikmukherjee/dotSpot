import json
import os
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional
from rich.console import Console

from utils.http import safe_get

console = Console()

PAYLOADS_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'payloads.json')


def load_payloads() -> Dict:
    try:
        with open(PAYLOADS_PATH, 'r') as f:
            data = json.load(f)
            return data.get('ssti', {})
    except Exception:
        return {
            "detection": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
            "expected_results": {
                "{{7*7}}": "49",
                "${7*7}": "49",
                "<%= 7*7 %>": "49"
            }
        }


def inject_parameter(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))


def detect_template_engine(response_text: str, payload: str, expected: str) -> Optional[str]:
    if expected in response_text:
        if payload.startswith("{{"):
            if ".__class__" in payload or "config" in payload:
                return "Jinja2"
            return "Jinja2/Twig"
        elif payload.startswith("${"):
            return "Freemarker/Velocity"
        elif payload.startswith("<%="):
            return "ERB/EJS"
        elif payload.startswith("#{"):
            return "Pebble"
        elif payload.startswith("*{"):
            return "Thymeleaf"
        elif payload.startswith("@("):
            return "Razor"
        return "Unknown Template Engine"
    return None


def test_ssti_detection(ctx, url: str, param: str, payloads: Dict):
    findings = []
    structured_results = []
    detection_payloads = payloads.get('detection', [])
    expected_results = payloads.get('expected_results', {})
    
    for payload in detection_payloads:
        test_url = inject_parameter(url, param, payload)
        response, error = safe_get(test_url)
        
        if error or not response:
            continue
        
        expected = expected_results.get(payload, "49")
        
        if expected in response.text:
            payload_reflected = payload in response.text
            result_present = expected in response.text
            
            if result_present and not payload_reflected:
                engine = detect_template_engine(response.text, payload, expected)
                info = f"Engine: {engine or 'Unknown'}, evaluated to '{expected}'"
                findings.append(
                    f"SSTI Vulnerability in parameter '{param}' "
                    f"(Engine: {engine or 'Unknown'}): payload '{payload}' evaluated to '{expected}'"
                )
                structured_results.append({
                    "url": url, "payload": payload, "info": info
                })
                break
            
            if result_present:
                payload_count = response.text.count(payload)
                result_count = response.text.count(expected)
                
                if result_count > payload_count:
                    engine = detect_template_engine(response.text, payload, expected)
                    info = f"Engine: {engine or 'Unknown'}, payload evaluated"
                    findings.append(
                        f"SSTI Vulnerability in parameter '{param}' "
                        f"(Engine: {engine or 'Unknown'}): payload evaluated"
                    )
                    structured_results.append({
                        "url": url, "payload": payload, "info": info
                    })
                    break
    
    return findings, structured_results


def test_advanced_ssti(ctx, url: str, param: str, payloads: Dict):
    findings = []
    structured_results = []
    
    engine_tests = {
        'jinja2': {
            'indicators': [
                "__class__", "__mro__", "__subclasses__",
                "<class", "uid=", "gid=", "/bin/", "root:"
            ]
        },
        'twig': {
            'indicators': [
                "registerUndefinedFilterCallback", "getFilter",
                "uid=", "gid=", "/bin/", "root:"
            ]
        },
        'freemarker': {
            'indicators': [
                "freemarker.template", "uid=", "gid=",
                "/bin/", "root:"
            ]
        },
    }
    
    for engine_name, config in engine_tests.items():
        engine_payloads = payloads.get(engine_name, [])
        for payload in engine_payloads[:3]:
            test_url = inject_parameter(url, param, payload)
            response, error = safe_get(test_url)
            
            if error or not response:
                continue
            
            for indicator in config['indicators']:
                if indicator in response.text:
                    info = f"RCE potential ({engine_name.title()}): '{indicator}' in response"
                    findings.append(
                        f"SSTI RCE potential in parameter '{param}' ({engine_name.title()}): "
                        f"Detected '{indicator}' in response"
                    )
                    structured_results.append({
                        "url": url, "payload": payload, "info": info
                    })
                    return findings, structured_results
    
    return findings, structured_results


def test_form_ssti(ctx, form: Dict, payloads: Dict):
    import requests
    from urllib.parse import urljoin
    
    findings = []
    structured_results = []
    
    raw_action = form.get('action', '')
    action = urljoin(ctx.base_url, raw_action) if raw_action else ctx.base_url
    method = form.get('method', 'GET').upper()
    inputs = form.get('inputs', [])
    
    if not inputs:
        return findings, structured_results
    
    base_data = {}
    text_inputs = []
    
    for inp in inputs:
        name = inp.get('name')
        if not name:
            continue
        input_type = inp.get('type', 'text').lower()
        value = inp.get('value', '')
        base_data[name] = value
        
        if input_type in ['text', 'password', 'email', 'search', 'textarea', '']:
            text_inputs.append(name)
    
    if not text_inputs:
        return findings, structured_results
    
    for name in text_inputs:
        if not base_data.get(name):
            base_data[name] = 'test'
    
    def send_form(data: Dict):
        try:
            if method == 'POST':
                return requests.post(action, data=data, timeout=5, verify=False, allow_redirects=True)
            else:
                return requests.get(action, params=data, timeout=5, verify=False, allow_redirects=True)
        except Exception:
            return None
    
    detection_payloads = payloads.get('detection', [])
    expected_results = payloads.get('expected_results', {})
    
    for payload in detection_payloads:
        test_data = base_data.copy()
        for field in text_inputs:
            test_data[field] = payload
        
        resp = send_form(test_data)
        if not resp:
            continue
        
        resp_text = resp.text
        expected = expected_results.get(payload, '49')
        
        if expected not in resp_text:
            continue
        
        payload_reflected = payload in resp_text
        
        if not payload_reflected:
            engine = detect_template_engine(resp_text, payload, expected)
            info = f"Engine: {engine or 'Unknown'}, evaluated to '{expected}'"
            findings.append(
                f"SSTI Vulnerability in form at {action} "
                f"(Engine: {engine or 'Unknown'}): payload '{payload}' evaluated to '{expected}'"
            )
            structured_results.append({
                "url": action, "payload": payload, "info": info
            })
            break
        
        if resp_text.count(expected) > resp_text.count(payload):
            engine = detect_template_engine(resp_text, payload, expected)
            info = f"Engine: {engine or 'Unknown'}, payload evaluated"
            findings.append(
                f"SSTI Vulnerability in form at {action} "
                f"(Engine: {engine or 'Unknown'}): payload evaluated"
            )
            structured_results.append({
                "url": action, "payload": payload, "info": info
            })
            break
    
    return findings, structured_results


def run(ctx):
    import requests
    requests.packages.urllib3.disable_warnings()
    
    payloads = load_payloads()
    
    if not hasattr(ctx, 'ssti_results'):
        ctx.ssti_results = []
    
    if hasattr(ctx, 'forms') and ctx.forms:
        tested_forms = set()
        
        for form in ctx.forms[:10]:
            action = form.get('action', '')
            form_key = f"{action}:{','.join(sorted([i.get('name','') for i in form.get('inputs', [])]))}"
            
            if form_key in tested_forms:
                continue
            tested_forms.add(form_key)
            
            form_findings, form_structured = test_form_ssti(ctx, form, payloads)
            ctx.findings.extend(form_findings)
            ctx.ssti_results.extend(form_structured)
    
    urls_to_test = []
    
    if hasattr(ctx, 'urls') and ctx.urls:
        for url in ctx.urls:
            parsed = urlparse(url)
            if parsed.query:
                urls_to_test.append(url)
    
    base_parsed = urlparse(ctx.base_url)
    if base_parsed.query:
        urls_to_test.append(ctx.base_url)
    
    if not urls_to_test:
        return
    
    tested_params = set()
    
    for url in urls_to_test[:10]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            param_key = f"{parsed.path}:{param}"
            if param_key in tested_params:
                continue
            tested_params.add(param_key)
            
            findings, structured = test_ssti_detection(ctx, url, param, payloads)
            ctx.findings.extend(findings)
            ctx.ssti_results.extend(structured)
            
            if findings:
                adv_findings, adv_structured = test_advanced_ssti(ctx, url, param, payloads)
                ctx.findings.extend(adv_findings)
                ctx.ssti_results.extend(adv_structured)
