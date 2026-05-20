import urllib.parse
import idna
import re
import math
import ipaddress

from collections import Counter
from urllib.parse import urlparse, urlunparse

from confusable_homoglyphs import confusables

# ──────────────────────────────────────────────
# URL Extraction Regex (Unicode Aware)
# ──────────────────────────────────────────────
EXTENDED_URL_REGEX = re.compile(
    r'https?://[^\s<>"\')\]]+|'
    r'www\.[^\s<>"\')\]]+|'
    r'(?<!@)\b(?:[\w\u0400-\u04FF]'
    r'(?:[\w\u0400-\u04FF\-]{0,61}[\w\u0400-\u04FF])?\.)+'
    r'(?:com|net|org|edu|gov|info|biz|cc|tv|xyz|site|online|tech|id|jp|ru|uk|us|mail|secure|lab|top|click|zip)\b'
    r'(?:/[^\s<>"\')\]]*)?|'
    r'data:[^\s<>"\']+|'
    r'javascript:[^\s<>"\']+',
    re.IGNORECASE | re.UNICODE
)

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "s.id", "cutt.ly", "rb.gy", "ow.ly",
    "short.io", "tiny.cc", "is.gd",
    "v.gd", "bl.ink", "soo.gd",
    "clck.ru", "rebrand.ly",
]

DANGEROUS_EXTENSIONS = [
    '.apk', '.exe', '.scr', '.bat',
    '.cmd', '.vbs', '.ps1', '.msi',
    '.jar', '.dmg', '.hta',
    '.pif', '.lnk', '.iso'
]

MACRO_EXTENSIONS = [
    '.xlsm', '.docm', '.xlsb',
    '.pptm', '.xltm', '.dotm',
    '.xlam', '.ppam'
]

IMPERSONATED_BRANDS = [
    "bca", "bri", "bni", "mandiri",
    "shopee", "tokopedia", "dana",
    "ovo", "gopay", "paypal",
    "google", "microsoft",
    "apple", "amazon", "whatsapp",
    "telegram", "instagram",
    "facebook", "netflix",
]

HIGH_RISK_KEYWORDS = [
    "verify", "verification", "wallet", "bonus",
    "reward", "gift", "otp", "invoice", "billing",
]

LOW_RISK_KEYWORDS = [
    "login", "secure", "account", "signin", "update",
]

RISKY_TLDS = [
    "xyz", "top", "click", "ru", "tk", "biz",
    "gq", "ml", "cf", "work", "zip"
]

NESTED_URL_PARAMETERS = [
    "url", "target", "redir", "redirect",
    "redirect_uri", "next", "continue",
]

# ──────────────────────────────────────────────
# Extraction
# ──────────────────────────────────────────────
def extract_urls_from_text(text: str) -> list:
    if not text:
        return []

    found_urls = EXTENDED_URL_REGEX.findall(text)
    cleaned_urls = []

    for u in found_urls:
        u = u.rstrip('.,;:!?)"\']')

        if u.lower().startswith(("data:", "javascript:")):
            if u not in cleaned_urls:
                cleaned_urls.append(u)
            continue

        if not u.lower().startswith(("http://", "https://")):
            u = "http://" + u

        if u not in cleaned_urls:
            cleaned_urls.append(u)

    return cleaned_urls


# ──────────────────────────────────────────────
# Normalization
# ──────────────────────────────────────────────
def normalize_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        if netloc.endswith(":80"):
            netloc = netloc[:-3]
        if netloc.endswith(":443"):
            netloc = netloc[:-4]

        path = re.sub(r'/+', '/', parsed.path)

        return urlunparse((
            scheme, netloc, path, '', parsed.query, ''
        ))
    except Exception:
        return url


# ──────────────────────────────────────────────
# Utility
# ──────────────────────────────────────────────
def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 3)


def is_ip_domain(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except Exception:
        return False


def tokenize_url(url: str) -> list:
    tokens = re.split(
        r'[\/\.\-\_\?\=\&\:\%\#]+',
        url.lower()
    )
    return [t for t in tokens if t]


# ──────────────────────────────────────────────
# Detection Functions
# ──────────────────────────────────────────────
def detect_file_risk(url: str) -> dict:
    lower = url.lower()
    clean_path = lower.split("?")[0].split("#")[0]

    dangerous = next(
        (e for e in DANGEROUS_EXTENSIONS if clean_path.endswith(e)),
        None
    )
    macro = next(
        (e for e in MACRO_EXTENSIONS if clean_path.endswith(e)),
        None
    )

    return {
        "has_dangerous_file": bool(dangerous),
        "dangerous_extension": dangerous or "-",
        "has_macro_file": bool(macro),
        "macro_extension": macro or "-"
    }


def detect_deceptive_subdomain(domain: str) -> dict:
    parts = domain.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    subdomain = ".".join(parts[:-2]) if len(parts) >= 3 else ""

    root_tokens = tokenize_url(root_domain)
    subdomain_tokens = tokenize_url(subdomain) if subdomain else []

    # A brand is deceptive only when it appears exclusively in the subdomain
    # portion, NOT in the root domain. This prevents false positives like
    # mx.google.com where "google" legitimately IS the root domain.
    found_brand = next(
        (b for b in IMPERSONATED_BRANDS
         if b in subdomain_tokens and b not in root_tokens),
        None
    )

    return {
        "deceptive_subdomain": bool(found_brand),
        "impersonated_brand": found_brand or "-",
        "real_domain": root_domain
    }


def detect_punycode(domain: str) -> tuple:
    parts = domain.split(".")
    has_punycode = any(p.startswith("xn--") for p in parts)
    decoded_parts = []

    for part in parts:
        if part.startswith("xn--"):
            try:
                decoded_parts.append(idna.decode(part))
            except Exception:
                decoded_parts.append(part)
        else:
            decoded_parts.append(part)

    decoded_domain = ".".join(decoded_parts)
    return has_punycode, decoded_domain


def detect_cyrillic(text: str) -> tuple:
    matches = list(set(re.findall(r'[\u0400-\u04FF]', text)))
    return bool(matches), matches


def detect_confusable(domain: str) -> bool:
    try:
        return bool(confusables.is_confusable(domain))
    except Exception:
        return False


def detect_suspicious_keywords(url: str) -> dict:
    lower = url.lower()
    high = [k for k in HIGH_RISK_KEYWORDS if k in lower]
    low = [k for k in LOW_RISK_KEYWORDS if k in lower]

    return {
        "high_risk_keywords": high,
        "low_risk_keywords": low
    }


def detect_risky_tld(domain: str) -> tuple:
    parts = domain.split(".")
    if not parts:
        return False, "-"

    tld = parts[-1].lower()
    return tld in RISKY_TLDS, tld


def detect_nested_url(parsed) -> bool:
    query_params = urllib.parse.parse_qs(parsed.query)

    for key, values in query_params.items():
        if key.lower() in NESTED_URL_PARAMETERS:
            for value in values:
                if value.startswith(("http://", "https://")):
                    return True
    return False


# ──────────────────────────────────────────────
# Hidden / Deceptive Link Detection
# ──────────────────────────────────────────────
HIDDEN_LINK_REGEX = re.compile(
    r'<a\s+[^>]*href\s*=\s*[\"\']([^\"\']+)[\"\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)


def clean_html_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def extract_hidden_links(html: str) -> list:
    if not html:
        return []

    findings = []
    matches = HIDDEN_LINK_REGEX.findall(html)

    for href, visible_text in matches:
        href = href.strip()
        visible_text = clean_html_text(visible_text)
        
        visible_urls = extract_urls_from_text(visible_text)
        href_urls = extract_urls_from_text(href)

        href_domain = ""
        visible_domain = ""
        href_url = ""
        visible_url = ""

        if href_urls:
            href_url = href_urls[0]
            try:
                href_domain = (urlparse(href_url).hostname or "").lower()
            except Exception:
                pass

        if visible_urls:
            visible_url = visible_urls[0]
            try:
                visible_domain = (urlparse(visible_url).hostname or "").lower()
            except Exception:
                pass

        href_domain = href_domain.strip()
        visible_domain = visible_domain.strip()

        # Punycode analysis
        href_punycode, href_decoded = detect_punycode(href_domain)
        visible_punycode, visible_decoded = detect_punycode(visible_domain)

        # Cyrillic analysis
        href_cyrillic, _ = detect_cyrillic(href_domain)
        visible_cyrillic, _ = detect_cyrillic(visible_domain)

        # Confusable
        href_confusable = detect_confusable(href_domain)
        visible_confusable = detect_confusable(visible_domain)

        # IP detection
        href_is_ip = is_ip_domain(href_domain)
        visible_is_ip = is_ip_domain(visible_domain)

        # Main mismatch detection
        mismatch = False
        if visible_domain and href_domain and visible_domain != href_domain:
            mismatch = True

        # Suspicious href schemes
        suspicious_scheme = href.lower().startswith(("javascript:", "data:"))

        # Nested redirect
        nested_redirect = False
        try:
            parsed_href = urlparse(href_url)
            nested_redirect = detect_nested_url(parsed_href)
        except Exception:
            pass

        # Risk scoring
        hidden_risk_score = 0

        if mismatch:
            hidden_risk_score += 3
        if suspicious_scheme:
            hidden_risk_score += 3
        if nested_redirect:
            hidden_risk_score += 2
        if href_punycode:
            hidden_risk_score += 2
        if href_cyrillic:
            hidden_risk_score += 2
        if href_confusable:
            hidden_risk_score += 1
        if href_is_ip:
            hidden_risk_score += 2

        # Final risk level
        if hidden_risk_score >= 6:
            hidden_risk_level = "TINGGI"
        elif hidden_risk_score >= 3:
            hidden_risk_level = "SEDANG"
        else:
            hidden_risk_level = "RENDAH"

        findings.append({
            "href": href,
            "visible_text": visible_text,
            "visible_url": visible_url or "-",
            "href_url": href_url or href,
            "visible_domain": visible_domain or "-",
            "href_domain": href_domain or "-",
            "is_hidden_link": mismatch,
            "suspicious_scheme": suspicious_scheme,
            "nested_redirect": nested_redirect,
            "href_punycode": href_punycode,
            "href_punycode_decoded": href_decoded if href_punycode else "-",
            "visible_punycode": visible_punycode,
            "visible_punycode_decoded": visible_decoded if visible_punycode else "-",
            "href_cyrillic": href_cyrillic,
            "visible_cyrillic": visible_cyrillic,
            "href_confusable": href_confusable,
            "visible_confusable": visible_confusable,
            "href_is_ip": href_is_ip,
            "visible_is_ip": visible_is_ip,
            "hidden_link_risk_score": hidden_risk_score,
            "hidden_link_risk_level": hidden_risk_level,
        })

    return findings


# ──────────────────────────────────────────────
# Main Analyzer
# ──────────────────────────────────────────────
def analyze_urls(urls: list) -> list:
    results = []

    for original_url in urls:
        normalized_url = normalize_url(original_url)
        parsed = urlparse(normalized_url)

        domain = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        decoded_url = urllib.parse.unquote(normalized_url)

        # Encoding
        encodings = re.findall(r'%[0-9a-fA-F]{2}', normalized_url)
        encoded = bool(encodings)

        # Punycode
        punycode, punycode_decoded = detect_punycode(domain)

        # Cyrillic
        cyrillic_domain, cyrillic_chars_domain = detect_cyrillic(domain)
        cyrillic_url, cyrillic_chars_url = detect_cyrillic(decoded_url)

        all_cyrillic = list(set(cyrillic_chars_domain + cyrillic_chars_url))
        cyrillic = bool(all_cyrillic)

        # Confusable
        confusable = detect_confusable(domain)

        # Shortener
        shortener = next(
            (s for s in SHORTENERS if domain == s or domain.endswith(f".{s}")),
            None
        )

        # File Risk
        file_risk = detect_file_risk(normalized_url)

        # Subdomain deception
        deceptive = detect_deceptive_subdomain(domain)

        # Keywords
        keyword_result = detect_suspicious_keywords(normalized_url)

        # Risky TLD
        risky_tld, detected_tld = detect_risky_tld(domain)

        # Nested URL
        nested_url = detect_nested_url(parsed)

        # IP domain
        is_ip = is_ip_domain(domain)

        # Entropy
        entropy = shannon_entropy(domain)

        # Statistics
        url_length = len(normalized_url)
        domain_length = len(domain)
        path_length = len(path)
        query_length = len(query)

        digit_count = sum(c.isdigit() for c in normalized_url)
        special_character_count = len(re.findall(r'[^a-zA-Z0-9]', normalized_url))
        subdomain_count = max(0, len(domain.split(".")) - 2)

        # Risk Scoring
        risk_score = 0

        if punycode:
            risk_score += 3
        if cyrillic:
            risk_score += 3
        if confusable:
            risk_score += 2
        if file_risk["has_dangerous_file"]:
            risk_score += 3
        if file_risk["has_macro_file"]:
            risk_score += 2
        if deceptive["deceptive_subdomain"]:
            risk_score += 2
        if shortener:
            risk_score += 1
        if encoded:
            risk_score += 1
        if risky_tld:
            risk_score += 1
        if nested_url:
            risk_score += 1
        if is_ip:
            risk_score += 2
        if entropy >= 4.5:
            risk_score += 1
        if len(keyword_result["high_risk_keywords"]) >= 1:
            risk_score += 1
        if len(keyword_result["low_risk_keywords"]) >= 2:
            risk_score += 1

        # Final Risk Level
        if risk_score >= 6:
            risk_level = "TINGGI"
        elif risk_score >= 3:
            risk_level = "SEDANG"
        else:
            risk_level = "RENDAH"

        results.append({
            "url": normalized_url,
            "domain": domain,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "decoded_url": decoded_url,
            "encoded": encoded,
            "encoded_chars": ", ".join(set(encodings)) if encodings else "-",
            "punycode": punycode,
            "punycode_decoded": punycode_decoded if punycode else "-",
            "cyrillic": cyrillic,
            "cyrillic_chars": ", ".join(all_cyrillic) if all_cyrillic else "-",
            "confusable": confusable,
            "shortlink": bool(shortener),
            "shortener_used": shortener or "-",
            "is_ip_address": is_ip,
            "risky_tld": risky_tld,
            "detected_tld": detected_tld,
            "nested_url": nested_url,
            "entropy": entropy,
            "url_length": url_length,
            "domain_length": domain_length,
            "path_length": path_length,
            "query_length": query_length,
            "digit_count": digit_count,
            "special_character_count": special_character_count,
            "subdomain_count": subdomain_count,
            "high_risk_keywords": keyword_result["high_risk_keywords"],
            "low_risk_keywords": keyword_result["low_risk_keywords"],
            "tokens": tokenize_url(normalized_url),
            **file_risk,
            **deceptive,
        })

    return results