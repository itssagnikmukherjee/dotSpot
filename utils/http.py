import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from functools import lru_cache
from typing import Optional, Dict, Any, Tuple
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 3
DEFAULT_HEADERS = {
    "User-Agent": "DotSpot/0.1 (Security Scanner)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}


def create_session(retries: int = 3, backoff_factor: float = 0.3) -> requests.Session:
    session = requests.Session()
    
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(DEFAULT_HEADERS)
    
    return session


_session: Optional[requests.Session] = None


def get_session() -> requests.Session:
    global _session
    if _session is None:
        _session = create_session()
    return _session


def safe_get(
    url: str,
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    verify_ssl: bool = False,
    allow_redirects: bool = True
) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        session = get_session()
        response = session.get(
            url,
            params=params,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=allow_redirects
        )
        return response, None
    except requests.exceptions.Timeout:
        return None, f"Timeout after {timeout}s"
    except requests.exceptions.ConnectionError:
        return None, "Connection failed"
    except requests.exceptions.TooManyRedirects:
        return None, "Too many redirects"
    except requests.exceptions.RequestException as e:
        return None, str(e)


def safe_post(
    url: str,
    data: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    verify_ssl: bool = False
) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        session = get_session()
        response = session.post(
            url,
            data=data,
            json=json,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl
        )
        return response, None
    except requests.exceptions.Timeout:
        return None, f"Timeout after {timeout}s"
    except requests.exceptions.ConnectionError:
        return None, "Connection failed"
    except requests.exceptions.RequestException as e:
        return None, str(e)


def get_response_time(url: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[float]:
    try:
        session = get_session()
        response = session.get(url, timeout=timeout, verify=False)
        return response.elapsed.total_seconds()
    except Exception:
        return None


def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')


def extract_domain(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc
