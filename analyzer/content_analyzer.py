"""
content_analyzer.py v8.1 — Analisis Konten Body Email (Full SE Taxonomy Sync)
======================================================
Perbaikan v8.1:
- SINKRONISASI PENUH dengan rag_engine.py SE_TAXONOMY (14 Kategori)
- Mengimpor _extract_email_body dari rag_engine (kebal terhadap sampah header EML)
- Menggunakan Regex Word Boundary (\b) untuk mencegah "kata hantu" (False Positive)
- Iterasi dinamis: Apapun yang ditambahkan di rag_engine otomatis terdeteksi di sini.
"""

import re
from analyzer.rag_engine import SE_TAXONOMY, _extract_email_body

KNOWN_TRACKING_DOMAINS = {
    "mandrillapp.com", "sendgrid.net", "mailchimp.com", "mailgun.org",
    "postmarkapp.com", "sparkpostmail.com", "ctmail.com", "cmail19.com",
    "cmail20.com", "createsend.com", "rsgsv.net", "list-manage.com",
    "mcsv.net", "mcdlv.net", "t.co",
}

def _match_taxonomy_keywords(text_lower: str, tactic_key: str) -> tuple:
    """
    Cocokkan keyword dari SE_TAXONOMY untuk satu kategori.
    Returns (count, matched_keywords_list).
    """
    tactic_info = SE_TAXONOMY.get(tactic_key, {})
    matched = set()

    all_indicators = tactic_info.get("indicators_id", []) + tactic_info.get("indicators_en", [])
    
    for word in all_indicators:
        pattern = r'\b' + re.escape(word.lower()) + r'\b'
        if re.search(pattern, text_lower):
            matched.add(word)

    matched_list = sorted(list(matched))
    return len(matched_list), matched_list

# Pola yang mengindikasikan email LEGITIMATE (mengurangi false positive)
LEGITIMATE_KEYWORDS_ID = [
    "jika anda tidak melakukan", "hubungi kami", "hubungi customer service",
    "pesanan anda telah", "transaksi anda telah", "terima kasih atas pembayaran",
    "terima kasih atas pesanan", "tidak perlu tindakan", "syarat dan ketentuan",
    "berhenti berlangganan",
]

LEGITIMATE_KEYWORDS_EN = [
    "if you did not", "if you didn't", "contact us", "contact customer service",
    "your order has been", "your transaction has been", "thank you for your payment",
    "thank you for your order", "no action needed", "no action is needed",
    "terms and conditions", "unsubscribe",
]

def _count_legitimate_signals(text_lower: str) -> int:
    count = 0
    all_legit = LEGITIMATE_KEYWORDS_ID + LEGITIMATE_KEYWORDS_EN
    for phrase in all_legit:
        pattern = r'\b' + re.escape(phrase.lower()) + r'\b'
        if re.search(pattern, text_lower):
            count += 1
    return count

def analyze_content(email_text: str) -> dict:
    if not email_text:
        return _empty_result()

    clean_body = _extract_email_body(email_text)
    if not clean_body:
        return _empty_result()

    text_lower = clean_body.lower()
    text_lower = re.sub(r'<style[^>]*>[\s\S]*?</style>', ' ', text_lower)
    text_lower = re.sub(r'<script[^>]*>[\s\S]*?</script>', ' ', text_lower)
    text_lower = re.sub(r'<[^>]+>', ' ', text_lower)

    legit_signals = _count_legitimate_signals(text_lower)
    result = {}
    total_indicators = 0

    # 🚀 Deteksi DINAMIS semua taktik yang ada di SE_TAXONOMY
    for tactic_key, tactic_info in SE_TAXONOMY.items():
        count, matches = _match_taxonomy_keywords(text_lower, tactic_key)
        result[tactic_key] = {
            "label": tactic_info.get("label", tactic_key.capitalize()),
            "description": tactic_info.get("description", ""),
            "count": count,
            "matches": matches,
            "detected": count > 0,
        }
        total_indicators += count

    link_mismatches = _detect_link_text_mismatch(email_text)
    has_hidden_form = bool(re.search(
        r'<form[^>]*>|<input[^>]*type=["\']hidden["\']',
        email_text, re.IGNORECASE
    ))
    has_tracking_pixel = bool(re.search(
        r'<img[^>]*(width|height)=["\']?[01]["\']?[^>]*(width|height)=["\']?[01]["\']?',
        email_text, re.IGNORECASE
    ))
    has_link_mismatch = len(link_mismatches) > 0

    result["link_text_mismatch"] = {
        "count": len(link_mismatches),
        "details": link_mismatches[:3],
        "detected": has_link_mismatch,
    }
    result["has_hidden_form"] = has_hidden_form
    result["has_tracking_pixel"] = has_tracking_pixel
    result["total_indicators"] = total_indicators
    result["legitimate_signals"] = legit_signals
    
    result["risk_summary"] = _classify_content_risk(result, has_link_mismatch, legit_signals)

    return result

def _detect_link_text_mismatch(text: str) -> list:
    mismatches = []
    pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
    for match in re.finditer(pattern, text, re.IGNORECASE):
        href = match.group(1).strip().lower()
        display = match.group(2).strip().lower()
        if not (display.startswith("http") or display.startswith("www")): continue
        href_domain = _extract_simple_domain(href)
        display_domain = _extract_simple_domain(display)
        # Skip known email tracking services (not actual phishing)
        is_tracking = any(
            href_domain == td or href_domain.endswith("." + td)
            for td in KNOWN_TRACKING_DOMAINS
        )
        if is_tracking:
            continue
        if href_domain and display_domain and href_domain != display_domain:
            mismatches.append({
                "displayed": display[:80], "actual_href": href[:80],
                "display_domain": display_domain, "href_domain": href_domain,
            })
    return mismatches

def _extract_simple_domain(url: str) -> str:
    url = url.lower().strip()
    if "://" in url: url = url.split("://", 1)[1]
    return url.split("/")[0].split(":")[0].split("?")[0]

def _classify_content_risk(se_results: dict, link_mismatch: bool, legit_signals: int = 0) -> str:
    score = 0
    # Bobot khusus untuk taktik berisiko sangat tinggi
    high_risk_tactics = ['urgency', 'fear', 'credential_request', 'reward', 'intimidation', 'emotional_manipulation']
    
    for tactic_key, data in se_results.items():
        if isinstance(data, dict) and "count" in data:
            count = data["count"]
            if count >= 2:
                score += 3 if tactic_key in high_risk_tactics else 2
            elif count == 1:
                score += 2 if tactic_key in high_risk_tactics else 1

    if link_mismatch: score += 2
    score -= legit_signals

    if score >= 5: return "TINGGI"
    elif score >= 2: return "SEDANG"
    return "RENDAH"

def _empty_result() -> dict:
    result = {}
    for tactic_key, tactic_info in SE_TAXONOMY.items():
        result[tactic_key] = {
            "label": tactic_info.get("label", tactic_key.capitalize()),
            "description": tactic_info.get("description", ""),
            "count": 0, "matches": [], "detected": False
        }
    result.update({
        "link_text_mismatch": {"count": 0, "details": [], "detected": False},
        "has_hidden_form": False,
        "has_tracking_pixel": False,
        "total_indicators": 0,
        "legitimate_signals": 0,
        "risk_summary": "RENDAH",
    })
    return result