import re
from typing import List, Pattern, Dict

SQL_ERROR_PATTERNS: List[Pattern] = [
    re.compile(r"SQL syntax.*?MySQL", re.IGNORECASE),
    re.compile(r"Warning.*?\Wmysqli?_", re.IGNORECASE),
    re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE),
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"check the manual that corresponds to your MySQL", re.IGNORECASE),
    
    re.compile(r"PostgreSQL.*?ERROR", re.IGNORECASE),
    re.compile(r"Warning.*?\Wpg_", re.IGNORECASE),
    re.compile(r"valid PostgreSQL result", re.IGNORECASE),
    re.compile(r"Npgsql\.", re.IGNORECASE),
    re.compile(r"PG::SyntaxError:", re.IGNORECASE),
    
    re.compile(r"Driver.*? SQL[\-\_\ ]*Server", re.IGNORECASE),
    re.compile(r"OLE DB.*? SQL Server", re.IGNORECASE),
    re.compile(r"\bSQL Server[^<\"]+Driver", re.IGNORECASE),
    re.compile(r"Warning.*?\W(mssql|sqlsrv)_", re.IGNORECASE),
    re.compile(r"\bSQL Server[^<\"]+[0-9a-fA-F]{8}", re.IGNORECASE),
    re.compile(r"System\.Data\.SqlClient\.", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
    
    re.compile(r"\bORA-\d{5}", re.IGNORECASE),
    re.compile(r"Oracle error", re.IGNORECASE),
    re.compile(r"Oracle.*?Driver", re.IGNORECASE),
    re.compile(r"Warning.*?\W(oci|ora)_", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    
    re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
    re.compile(r"SQLite\.Exception", re.IGNORECASE),
    re.compile(r"System\.Data\.SQLite\.SQLiteException", re.IGNORECASE),
    re.compile(r"\[SQLITE_ERROR\]", re.IGNORECASE),
    re.compile(r"SQLITE_CONSTRAINT", re.IGNORECASE),
    
    re.compile(r"SQL syntax.*?error", re.IGNORECASE),
    re.compile(r"syntax error.*?SQL", re.IGNORECASE),
    re.compile(r"Unclosed.*?quotation", re.IGNORECASE),
    re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
    
    re.compile(r"Syntax error.*?Encountered", re.IGNORECASE),
    re.compile(r"syntax error at or near", re.IGNORECASE),
    re.compile(r"unexpected end of SQL", re.IGNORECASE),
    re.compile(r"SQL command not properly ended", re.IGNORECASE),
    re.compile(r"Invalid column name", re.IGNORECASE),
    re.compile(r"Unknown column", re.IGNORECASE),
    re.compile(r"Query failed", re.IGNORECASE),
]

SECRET_PATTERNS: Dict[str, Pattern] = {
    "aws_access_key": re.compile(r"(AKIA[0-9A-Z]{16})"),
    "aws_secret_key": re.compile(r"(?i)(aws|amazon).{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "github_token": re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}"),
    "stripe_key": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|apikey)['\"\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),
    "generic_secret": re.compile(r"(?i)(secret|password|passwd|pwd)['\"\s:=]+['\"]?([^\s'\"]{8,})['\"]?"),
    "bearer_token": re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+"),
    "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
    
    "database_uri": re.compile(r"(?i)(mysql|postgres|postgresql|mongodb|redis|sqlite):\/\/[^\s\"'<>]+"),
    
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
}

COMMENT_PATTERNS: Dict[str, Pattern] = {
    "todo_fixme": re.compile(r"(?i)(TODO|FIXME|HACK|XXX|BUG)[\s:]+.{5,}"),
    "password_comment": re.compile(r"(?i)password\s*(is|:|=)\s*['\"]?[^\s'\"]+"),
    "credentials": re.compile(r"(?i)(username|user|login|email)[:\s]+\S+.*?(password|pwd|pass)[:\s]+\S+"),
    "debug_info": re.compile(r"(?i)(debug|test|temp|staging|dev).*?(mode|server|env|api)"),
    "internal_urls": re.compile(r"(?i)(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)[^\s\"'<>]*"),
}

XSS_REFLECTION_PATTERNS: List[Pattern] = [
    re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on(load|error|click|mouseover|focus|blur)\s*=", re.IGNORECASE),
    re.compile(r"<img[^>]+src\s*=\s*['\"]?javascript:", re.IGNORECASE),
]


def find_sql_errors(text: str) -> List[str]:
    errors = []
    for pattern in SQL_ERROR_PATTERNS:
        matches = pattern.findall(text)
        errors.extend(matches)
    return errors


def find_secrets(text: str) -> Dict[str, List[str]]:
    secrets = {}
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            secrets[secret_type] = matches
    return secrets


def find_sensitive_comments(text: str) -> Dict[str, List[str]]:
    comments = {}
    for comment_type, pattern in COMMENT_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            comments[comment_type] = [str(m) for m in matches]
    return comments


def check_xss_reflection(payload: str, response: str) -> bool:
    if payload in response:
        for pattern in XSS_REFLECTION_PATTERNS:
            if pattern.search(response):
                return True
    return False
