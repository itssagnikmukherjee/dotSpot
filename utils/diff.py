from difflib import SequenceMatcher
from typing import Optional, Tuple
import hashlib
import re


def similarity_ratio(text1: str, text2: str) -> float:
    if not text1 and not text2:
        return 1.0
    if not text1 or not text2:
        return 0.0
    return SequenceMatcher(None, text1, text2).ratio()


def content_hash(text: str) -> str:
    normalized = re.sub(r'\s+', ' ', text.lower().strip())
    return hashlib.md5(normalized.encode()).hexdigest()


def normalize_response(text: str) -> str:
    text = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', '[TIMESTAMP]', text)
    text = re.sub(r'[a-f0-9]{32,}', '[TOKEN]', text, flags=re.IGNORECASE)
    text = re.sub(r'csrf[_-]?token["\s:=]+["\']?[a-zA-Z0-9_-]+["\']?', '[CSRF]', text, flags=re.IGNORECASE)
    text = re.sub(r'nonce["\s:=]+["\']?[a-zA-Z0-9_-]+["\']?', '[NONCE]', text, flags=re.IGNORECASE)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def responses_differ(response1: str, response2: str, threshold: float = 0.95) -> bool:
    norm1 = normalize_response(response1)
    norm2 = normalize_response(response2)
    similarity = similarity_ratio(norm1, norm2)
    return similarity < threshold


def detect_boolean_difference(
    true_response: str,
    false_response: str,
    baseline_response: str
) -> Tuple[bool, str]:
    true_norm = normalize_response(true_response)
    false_norm = normalize_response(false_response)
    base_norm = normalize_response(baseline_response)
    
    true_sim = similarity_ratio(true_norm, base_norm)
    false_sim = similarity_ratio(false_norm, base_norm)
    
    if true_sim > 0.9 and false_sim < 0.7:
        return True, f"True condition matches baseline ({true_sim:.2f}), false differs ({false_sim:.2f})"
    
    true_false_diff = similarity_ratio(true_norm, false_norm)
    if true_false_diff < 0.7:
        return True, f"True and false responses differ significantly ({true_false_diff:.2f})"
    
    return False, "No significant difference detected"


def length_difference(response1: str, response2: str) -> int:
    return abs(len(response1) - len(response2))


def word_difference(response1: str, response2: str) -> int:
    words1 = len(response1.split())
    words2 = len(response2.split())
    return abs(words1 - words2)


def detect_time_based_difference(
    normal_time: float,
    injected_time: float,
    delay_threshold: float = 4.0
) -> Tuple[bool, str]:
    time_diff = injected_time - normal_time
    
    if time_diff >= delay_threshold:
        return True, f"Response delayed by {time_diff:.2f}s (threshold: {delay_threshold}s)"
    
    return False, f"No significant delay detected ({time_diff:.2f}s)"
