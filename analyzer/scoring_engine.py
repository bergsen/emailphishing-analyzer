from urllib.parse import urlparse
import math

# Konstanta — Weight Rebalanced
WEIGHTS = {
    # ═══════════════════════════════════════════
    # S_A — Autentikasi Email & Header (max 25)
    # Indikator berbasis header email
    # ═══════════════════════════════════════════
    "dmarc_fail":          {"score": 12, "label": "DMARC gagal/tidak ada",               "category": "S_A"},
    "spf_fail":            {"score": 10, "label": "SPF gagal/tidak ada",                 "category": "S_A"},
    "dkim_fail":           {"score":  8, "label": "DKIM gagal/tidak ada",                "category": "S_A"},
    "domain_mismatch":     {"score": 10, "label": "Domain From ≠ Return-Path",            "category": "S_A"},
    "all_auth_missing":    {"score":  5, "label": "Autentikasi tidak tersedia (input teks)", "category": "S_A"},
    "reply_to_mismatch":   {"score":  8, "label": "Reply-To ≠ From (mencurigakan)",      "category": "S_A"},
    "suspicious_hop":      {"score":  5, "label": "Received header mencurigakan",         "category": "S_A"},
    "suspicious_mailer":   {"score":  3, "label": "X-Mailer mencurigakan",                "category": "S_A"},

    # ═══════════════════════════════════════════
    # S_B — Analisis URL & File/Attachment (max 30)
    # Bukti teknis langsung — PRIORITAS TERTINGGI
    # ═══════════════════════════════════════════
    "punycode":            {"score": 25, "label": "Homograph / Punycode (kritis)",        "category": "S_B"},
    "cyrillic":            {"score": 25, "label": "Karakter Cyrillic (kritis)",           "category": "S_B"},
    "dangerous_ext":       {"score": 30, "label": "File payload berbahaya",               "category": "S_B"},
    "macro_ext":           {"score": 20, "label": "Dokumen bermakro",                     "category": "S_B"},
    "shortlink":           {"score":  5, "label": "URL shortener terdeteksi",             "category": "S_B"},
    "encoded_auth_fail":   {"score":  6, "label": "URL encoding + auth gagal",            "category": "S_B"},
    "data_uri":            {"score": 25, "label": "Data URI berbahaya terdeteksi",        "category": "S_B"},
    "js_uri":              {"score": 25, "label": "JavaScript URI terdeteksi",            "category": "S_B"},
    "attachment_dangerous": {"score": 28, "label": "Attachment file berbahaya",           "category": "S_B"},
    "attachment_macro":    {"score": 20, "label": "Attachment dokumen bermakro",          "category": "S_B"},
    "double_extension":    {"score": 18, "label": "Attachment double extension",          "category": "S_B"},
    "deceptive_subdomain": {"score": 12, "label": "Subdomain menyamar brand",            "category": "S_B"},

    # ═══════════════════════════════════════════
    # S_C — Konten & Social Engineering (max 20)
    # Faktor pendukung — BOBOT DITURUNKAN
    # Keyword NLP noisy, tidak boleh dominan
    # ═══════════════════════════════════════════
    "urgency_detected":    {"score":  5, "label": "Pola urgensi/tekanan terdeteksi",      "category": "S_C"},
    "fear_detected":       {"score":  6, "label": "Bahasa ancaman/intimidasi",            "category": "S_C"},
    "authority_detected":  {"score":  5, "label": "Pola impersonasi otoritas",            "category": "S_C"},
    "reward_scam_pattern": {"score":  5, "label": "Pola scam hadiah/undian",              "category": "S_C"},
    "secrecy_detected":    {"score":  5, "label": "Pola kerahasiaan mencurigakan",        "category": "S_C"},
    "sextortion_detected": {"score": 20, "label": "Pola sextortion/pemerasan digital",   "category": "S_C"},
    "credential_request":  {"score": 10, "label": "Permintaan kredensial terdeteksi",     "category": "S_C"},
    "link_text_mismatch":  {"score": 10, "label": "Teks link ≠ tujuan sebenarnya",       "category": "S_C"},
    "rag_high_similarity": {"score":  10, "label": "Kemiripan tinggi dengan pola phishing (RAG)", "category": "S_C"},
    "rag_medium_similarity": {"score":  5, "label": "Kemiripan sedang dengan pola phishing (RAG)", "category": "S_C"},

    # ═══════════════════════════════════════════
    # S_D — Reputasi Domain & Redirect (max 25)
    # Supporting signal — BUKAN bukti utama
    # Non-linear scaling untuk OSINT
    # ═══════════════════════════════════════════
    "very_new_domain":       {"score": 15, "label": "Domain sangat baru (< 30 hari)",     "category": "S_D"},
    "new_domain":            {"score":  8, "label": "Domain baru (30–90 hari)",           "category": "S_D"},
    "ip_not_found":          {"score":  5, "label": "IP server tidak ditemukan",          "category": "S_D"},
    "virustotal_low":        {"score":  5, "label": "VirusTotal: 1-2 engine",             "category": "S_D"},
    "virustotal_medium":     {"score": 10, "label": "VirusTotal: 3-5 engine",             "category": "S_D"},
    "virustotal_high":       {"score": 18, "label": "VirusTotal: >5 engine",              "category": "S_D"},
    "abuseipdb_low":         {"score":  5, "label": "AbuseIPDB: skor rendah",             "category": "S_D"},
    "abuseipdb_medium":      {"score":  8, "label": "AbuseIPDB: skor sedang (25-50%)",    "category": "S_D"},
    "abuseipdb_high":        {"score": 15, "label": "AbuseIPDB: skor tinggi (>50%)",      "category": "S_D"},
    "tor_exit_node":         {"score":  8, "label": "IP adalah Tor exit node",            "category": "S_D"},
    "urlscan_malicious":     {"score": 12, "label": "Terdeteksi berbahaya di URLScan.io", "category": "S_D"},
    "cross_domain_redirect": {"score":  8, "label": "Redirect lintas domain",             "category": "S_D"},
    "url_unreachable":       {"score":  4, "label": "URL tidak dapat dijangkau",          "category": "S_D"},
    "long_redirect_chain":   {"score":  5, "label": "Rantai redirect terlalu panjang",    "category": "S_D"},
}

# Cap per kategori (Rebalanced)
CAPS = {
    "S_A": 25,   # Autentikasi Email
    "S_B": 30,   # URL & File (prioritas tertinggi — bukti teknis langsung)
    "S_C": 25,   # Konten & SE (faktor pendukung — dinaikkan untuk menampung sextortion)
    "S_D": 25,   # Reputasi & Redirect (supporting signal)
}

# Bonus (pengurang skor) untuk indikator legitimate — DIPERKUAT
BONUS_AUTH_ALL_PASS = -10   # SPF+DKIM+DMARC pass (dikurangi: phishing modern bisa pass auth)
BONUS_WHITELISTED   = -10   # Domain whitelisted (dikurangi: compromised domain mungkin)
BONUS_AUTH_PARTIAL  = -3    # SPF parsial
BONUS_LEGITIMATE_PATTERN = -20 # Mencegah false positive dari analisis RAG


# ──────────────────────────────────────────────
# Fungsi Utilitas
# ──────────────────────────────────────────────
def _get_netloc(url: str) -> str:
    try:
        return urlparse(url).netloc or url.split("/")[0]
    except Exception:
        return ""


def _flag(key: str, detail: str = "") -> dict:
    w = WEIGHTS[key]
    return {
        "key": key,
        "category": w["category"],
        "label": w["label"] + (f" — {detail}" if detail else ""),
        "weight": w["score"],
    }


def _bonus_flag(label: str, bonus: int) -> dict:
    return {
        "key": "bonus",
        "category": "BONUS",
        "label": label,
        "weight": bonus,
    }


# ──────────────────────────────────────────────
# S_A: Autentikasi Email & Header
# ──────────────────────────────────────────────
def _score_auth(spoof: dict, rag_context: dict = None) -> tuple:
    flags = []
    s = 0
    # is_whitelisted = (rag_context or {}).get("is_whitelisted", False) # Boleh dihapus dari fungsi ini

    if spoof.get("dmarc_fail"):
        s += WEIGHTS["dmarc_fail"]["score"]
        flags.append(_flag("dmarc_fail"))

    if spoof.get("spf_fail"):
        s += WEIGHTS["spf_fail"]["score"]
        flags.append(_flag("spf_fail"))

    if spoof.get("dkim_fail"):
        s += WEIGHTS["dkim_fail"]["score"]
        flags.append(_flag("dkim_fail"))

    # 🚀 FIX: Jangan maafkan "auth missing" untuk domain apapun. Brand besar wajib punya Auth!
    if spoof.get("all_auth_missing"):
        s += WEIGHTS["all_auth_missing"]["score"]
        flags.append(_flag("all_auth_missing"))

    # 🚀 FIX: Jangan maafkan Domain Mismatch hanya karena dia Whitelisted!
    if spoof.get("domain_mismatch"):
        if spoof.get("dmarc_status") == "pass":
            pass # DMARC pass berarti mismatch ini sah (misal via mailing list resmi)
        else:
            s += WEIGHTS["domain_mismatch"]["score"]
            flags.append(_flag("domain_mismatch",
                               f"{spoof.get('root_from', '-')} ≠ {spoof.get('root_return', '-')}"))

    if spoof.get("reply_to_mismatch"):
        s += WEIGHTS["reply_to_mismatch"]["score"]
        flags.append(_flag("reply_to_mismatch",
                           f"Reply-To: {spoof.get('reply_to_domain', '-')}"))

    if spoof.get("has_suspicious_hops"):
        s += WEIGHTS["suspicious_hop"]["score"]
        hop_count = len(spoof.get("suspicious_hops", []))
        flags.append(_flag("suspicious_hop", f"{hop_count} hop(s) mencurigakan"))

    if spoof.get("suspicious_mailer"):
        s += WEIGHTS["suspicious_mailer"]["score"]
        flags.append(_flag("suspicious_mailer", spoof.get("x_mailer", "")))

    return s, flags  # Ingat, kembalikan RAW score (tanpa min/cap) karena sudah kita perbaiki sebelumnya


# ──────────────────────────────────────────────
# S_B: Analisis URL & File/Attachment
# Bukti teknis langsung — prioritas tertinggi
# ──────────────────────────────────────────────
def _score_urls(url_list: list, spoof: dict,
                attachment_analysis: dict = None) -> tuple:
    """
    S_B: Analisis teknis URL & Attachment.
    Indikator ini merupakan hard evidence yang sulit dipalsukan.
    """
    flags = []
    s = 0
    seen = set()

    auth_fail = spoof.get("spf_fail") or spoof.get("dkim_fail")

    for item in url_list:
        if item.get("is_data_uri") and "data_uri" not in seen:
            seen.add("data_uri")
            s += WEIGHTS["data_uri"]["score"]
            flags.append(_flag("data_uri"))

        if item.get("is_javascript_uri") and "js_uri" not in seen:
            seen.add("js_uri")
            s += WEIGHTS["js_uri"]["score"]
            flags.append(_flag("js_uri"))

        if item.get("punycode") and "punycode" not in seen:
            seen.add("punycode")
            s += WEIGHTS["punycode"]["score"]
            flags.append(_flag("punycode", item.get("punycode_decoded", "")))

        if item.get("cyrillic") and "cyrillic" not in seen:
            seen.add("cyrillic")
            s += WEIGHTS["cyrillic"]["score"]
            flags.append(_flag("cyrillic", item.get("cyrillic_chars", "")))

        if item.get("has_dangerous_file") and "dangerous_ext" not in seen:
            seen.add("dangerous_ext")
            s += WEIGHTS["dangerous_ext"]["score"]
            flags.append(_flag("dangerous_ext", item.get("dangerous_extension", "")))

        if item.get("has_macro_file") and "macro_ext" not in seen:
            seen.add("macro_ext")
            s += WEIGHTS["macro_ext"]["score"]
            flags.append(_flag("macro_ext", item.get("macro_extension", "")))

        if item.get("shortlink") and "shortlink" not in seen:
            seen.add("shortlink")
            s += WEIGHTS["shortlink"]["score"]
            flags.append(_flag("shortlink", item.get("shortener_used", "")))

        if item.get("deceptive_subdomain") and "deceptive_subdomain" not in seen:
            seen.add("deceptive_subdomain")
            s += WEIGHTS["deceptive_subdomain"]["score"]
            flags.append(_flag("deceptive_subdomain",
                               f"{item.get('impersonated_brand', '')} @ {item.get('real_domain', '')}"))

        if item.get("encoded") and auth_fail and "encoded_auth_fail" not in seen:
            seen.add("encoded_auth_fail")
            s += WEIGHTS["encoded_auth_fail"]["score"]
            flags.append(_flag("encoded_auth_fail"))

    # Attachment scoring — hard evidence
    if attachment_analysis:
        if attachment_analysis.get("has_dangerous") and "attachment_dangerous" not in seen:
            seen.add("attachment_dangerous")
            s += WEIGHTS["attachment_dangerous"]["score"]
            count = attachment_analysis.get("dangerous_count", 0)
            flags.append(_flag("attachment_dangerous", f"{count} file berbahaya"))

        if attachment_analysis.get("has_macro") and "attachment_macro" not in seen:
            seen.add("attachment_macro")
            s += WEIGHTS["attachment_macro"]["score"]
            count = attachment_analysis.get("macro_count", 0)
            flags.append(_flag("attachment_macro", f"{count} file bermakro"))

        if attachment_analysis.get("has_double_extension") and "double_extension" not in seen:
            seen.add("double_extension")
            s += WEIGHTS["double_extension"]["score"]
            flags.append(_flag("double_extension"))

    return s, flags


# ──────────────────────────────────────────────
# S_C: Konten & Social Engineering
# Faktor pendukung — threshold ketat, anti false-positive
# ──────────────────────────────────────────────
def _score_content(content_analysis: dict = None,
                   rag_context: dict = None,
                   spoof: dict = None) -> tuple:
    """
    S_C: Konten & Social Engineering.

    Prinsip:
    - Keyword NLP bersifat noisy → threshold minimal 2-3 keyword
    - Jika email terautentikasi (SPF+DKIM+DMARC pass atau whitelisted),
      threshold lebih tinggi untuk mengurangi false positive
    - RAG similarity hanya faktor pendukung (threshold HIGH >= 0.60)
    - Tidak ada double counting antar indikator
    """
    flags = []
    s = 0
    seen = set()

    is_whitelisted = (rag_context or {}).get("is_whitelisted", False)
    auth_all_pass = False
    if spoof:
        auth_all_pass = (
            spoof.get("spf_status") == "pass"
            and spoof.get("dkim_status") == "pass"
            and spoof.get("dmarc_status") == "pass"
        )
    is_likely_legit = auth_all_pass or is_whitelisted

    # ── Content Analysis indicators ──
    if content_analysis:
        # Urgency — minimal 2 keyword, atau 3 jika likely legit
        urgency = content_analysis.get("urgency", {})
        urgency_threshold = 3 if is_likely_legit else 2
        if urgency.get("detected") and urgency.get("count", 0) >= urgency_threshold:
            if "urgency_detected" not in seen:
                seen.add("urgency_detected")
                s += WEIGHTS["urgency_detected"]["score"]
                matches = ", ".join(urgency.get("matches", [])[:3])
                flags.append(_flag("urgency_detected", matches))

        # Fear / Ancaman — minimal 1 keyword, atau 2 jika likely legit
        fear = content_analysis.get("fear", {})
        fear_threshold = 2 if is_likely_legit else 1
        if fear.get("detected") and fear.get("count", 0) >= fear_threshold:
            if "fear_detected" not in seen:
                seen.add("fear_detected")
                s += WEIGHTS["fear_detected"]["score"]
                matches = ", ".join(fear.get("matches", [])[:3])
                flags.append(_flag("fear_detected", matches))

        # Authority / Impersonasi — minimal 1 keyword, atau 2 jika likely legit
        authority = content_analysis.get("authority", {})
        authority_threshold = 2 if is_likely_legit else 1
        if authority.get("detected") and authority.get("count", 0) >= authority_threshold:
            if "authority_detected" not in seen:
                seen.add("authority_detected")
                s += WEIGHTS["authority_detected"]["score"]
                matches = ", ".join(authority.get("matches", [])[:3])
                flags.append(_flag("authority_detected", matches))

        # Reward / Iming-iming — minimal 2 keyword, atau 3 jika likely legit
        reward = content_analysis.get("reward", {})
        reward_threshold = 3 if is_likely_legit else 2
        if reward.get("detected") and reward.get("count", 0) >= reward_threshold:
            if "reward_scam_pattern" not in seen:
                seen.add("reward_scam_pattern")
                s += WEIGHTS["reward_scam_pattern"]["score"]
                matches = ", ".join(reward.get("matches", [])[:3])
                flags.append(_flag("reward_scam_pattern", matches))

        # Secrecy / Kerahasiaan — minimal 2 keyword, atau 3 jika likely legit
        secrecy = content_analysis.get("secrecy", {})
        secrecy_threshold = 3 if is_likely_legit else 2
        if secrecy.get("detected") and secrecy.get("count", 0) >= secrecy_threshold:
            if "secrecy_detected" not in seen:
                seen.add("secrecy_detected")
                s += WEIGHTS["secrecy_detected"]["score"]
                matches = ", ".join(secrecy.get("matches", [])[:3])
                flags.append(_flag("secrecy_detected", matches))

        # Sextortion / Pemerasan Digital — KRITIS (hard indicator)
        # Deteksi pola pemerasan: Bitcoin wallet + ancaman + akses perangkat
        sextortion = content_analysis.get("sextortion", {})
        if sextortion.get("detected") and sextortion.get("count", 0) >= 3:
            if "sextortion_detected" not in seen:
                seen.add("sextortion_detected")
                s += WEIGHTS["sextortion_detected"]["score"]
                matches = ", ".join(sextortion.get("matches", [])[:5])
                flags.append(_flag("sextortion_detected", matches))

        # Permintaan kredensial — sangat sensitif (hard indicator)
        cred = content_analysis.get("credential_request", {})
        if cred.get("detected"):
            cred_count = cred.get("count", 0)
            cred_threshold = 2 if is_likely_legit else 1
            if cred_count >= cred_threshold:
                if "credential_request" not in seen:
                    seen.add("credential_request")
                    s += WEIGHTS["credential_request"]["score"]
                    matches = ", ".join(cred.get("matches", [])[:3])
                    flags.append(_flag("credential_request", matches))

        # Link-text mismatch — teknis, tetap sensitif
        ltm = content_analysis.get("link_text_mismatch", {})
        if ltm.get("detected") and "link_text_mismatch" not in seen:
            seen.add("link_text_mismatch")
            s += WEIGHTS["link_text_mismatch"]["score"]
            flags.append(_flag("link_text_mismatch",
                               f"{ltm.get('count', 0)} mismatch"))

    # ── RAG Similarity (realistis untuk TF-IDF cosine similarity) ──
    # Threshold realistis: HIGH >= 0.25, MEDIUM >= 0.12
    # TF-IDF cosine similarity jarang > 0.35 untuk teks pendek
    if rag_context:
        highest_sim = rag_context.get("highest_similarity", 0)
        cat = rag_context.get("highest_match_category", "").lower()
        rag_risk = rag_context.get("rag_risk_level", "TINGGI")

        # PENCEGAHAN FALSE POSITIVE: Jangan tambahkan penalti phishing jika RAG mendeteksi ini sebagai email legitimate
        if cat not in ["legitimate", "safe", "informative"] and rag_risk not in ["RENDAH", "AMAN"]:
            if highest_sim >= 0.25:
                if "rag_high_similarity" not in seen:
                    seen.add("rag_high_similarity")
                    s += WEIGHTS["rag_high_similarity"]["score"]
                    cat_label = rag_context.get("highest_match_category", "")
                    flags.append(_flag("rag_high_similarity",
                                       f"{highest_sim:.0%} match [{cat_label}]"))
            elif highest_sim >= 0.12:
                if "rag_medium_similarity" not in seen:
                    seen.add("rag_medium_similarity")
                    s += WEIGHTS["rag_medium_similarity"]["score"]
                    cat_label = rag_context.get("highest_match_category", "")
                    flags.append(_flag("rag_medium_similarity",
                                       f"{highest_sim:.0%} match [{cat_label}]"))

    return s, flags


# ──────────────────────────────────────────────
# S_D: Reputasi Domain & Redirect
# Supporting signal — non-linear, dependency on S_B
# ──────────────────────────────────────────────
def _score_domain_redirect(domain_info: dict,
                           all_redirects: list,
                           s_b_score: int = 0) -> tuple:
    """
    S_D: Reputasi Domain & IP + Rantai Redirect.

    Prinsip:
    - Non-linear scaling untuk OSINT (VirusTotal, AbuseIPDB)
    - Dependency rule: jika S_B == 0 (tidak ada bukti teknis), S_D dikurangi 20%
    - Reputasi OSINT tidak bisa berdiri sendiri sebagai bukti phishing
    """
    flags = []
    s = 0

    # ── Domain Reputation ──
    all_results = domain_info.get("all_results", [domain_info])
    primary = domain_info.get("primary", domain_info)

    # Domain age
    age = primary.get("domain_age")
    if age not in ("-", None, ""):
        try:
            age_int = int(age)
            if age_int < 30:
                s += WEIGHTS["very_new_domain"]["score"]
                flags.append(_flag("very_new_domain", f"{age_int} hari"))
            elif age_int < 90:
                s += WEIGHTS["new_domain"]["score"]
                flags.append(_flag("new_domain", f"{age_int} hari"))
        except (ValueError, TypeError):
            pass

    if primary.get("ip_address") in ("Tidak Ditemukan", None, "", "N/A"):
        s += WEIGHTS["ip_not_found"]["score"]
        flags.append(_flag("ip_not_found"))

    # VirusTotal — NON-LINEAR scoring
    total_vt = domain_info.get("total_vt_positives",
                               primary.get("virustotal_positives", 0)) or 0
    max_vt = domain_info.get("max_vt_positives", total_vt)

    if max_vt > 5:
        s += WEIGHTS["virustotal_high"]["score"]
        flags.append(_flag("virustotal_high", f"{max_vt} engine(s)"))
    elif max_vt >= 3:
        s += WEIGHTS["virustotal_medium"]["score"]
        flags.append(_flag("virustotal_medium", f"{max_vt} engine(s)"))
    elif max_vt >= 1:
        s += WEIGHTS["virustotal_low"]["score"]
        flags.append(_flag("virustotal_low", f"{max_vt} engine(s)"))

    # AbuseIPDB — NON-LINEAR (logarithmic-like) scoring
    max_abuse = domain_info.get("max_abuseipdb_score", 0)
    if max_abuse <= 0:
        max_abuse = primary.get("abuseipdb_score", 0) or 0

    if max_abuse > 50:
        s += WEIGHTS["abuseipdb_high"]["score"]
        flags.append(_flag("abuseipdb_high", f"confidence {max_abuse}%"))
    elif max_abuse > 25:
        s += WEIGHTS["abuseipdb_medium"]["score"]
        flags.append(_flag("abuseipdb_medium", f"confidence {max_abuse}%"))
    elif max_abuse > 0 or domain_info.get("has_abuseipdb_hit", False):
        s += WEIGHTS["abuseipdb_low"]["score"]
        abuse_reports = sum(r.get("abuseipdb_reports", 0) for r in all_results)
        flags.append(_flag("abuseipdb_low", f"{abuse_reports} laporan"))

    # Tor exit node
    for r in all_results:
        if r.get("abuseipdb_is_tor"):
            s += WEIGHTS["tor_exit_node"]["score"]
            flags.append(_flag("tor_exit_node"))
            break

    # URLScan.io
    if domain_info.get("has_urlscan_malicious", False):
        s += WEIGHTS["urlscan_malicious"]["score"]
        flags.append(_flag("urlscan_malicious"))

    # ── Redirect Analysis ──
    seen_flags = set()

    if all_redirects:
        for redirect_result in all_redirects:
            chain = redirect_result.get("chain", [])
            if not chain:
                continue

            if redirect_result.get("has_cross_domain") and "cross_domain_redirect" not in seen_flags:
                first_domain = _get_netloc(chain[0].get("url", ""))
                last_domain = _get_netloc(chain[-1].get("url", ""))
                s += WEIGHTS["cross_domain_redirect"]["score"]
                seen_flags.add("cross_domain_redirect")
                flags.append(_flag("cross_domain_redirect", f"{first_domain} → {last_domain}"))

            if len(chain) > 5 and "long_redirect_chain" not in seen_flags:
                s += WEIGHTS["long_redirect_chain"]["score"]
                seen_flags.add("long_redirect_chain")
                flags.append(_flag("long_redirect_chain", f"{len(chain)} hops"))

            for r in chain:
                status = str(r.get("status", "")).lower()
                if "error" in status or "unreachable" in status or status.startswith(('4', '5')):
                    if "url_unreachable" not in seen_flags:
                        s += WEIGHTS["url_unreachable"]["score"]
                        seen_flags.add("url_unreachable")
                        flags.append(_flag("url_unreachable", f"HTTP {status}"))
                    break

    # ── DEPENDENCY RULE ──
    raw_s = s
    if s_b_score == 0 and s > 0:
        s = int(s * 0.8)  

    return s, flags


# ──────────────────────────────────────────────
# Bonus Legitimasi (diperbaiki untuk Forwarded)
# ──────────────────────────────────────────────
def _calculate_bonus(spoof: dict, rag_context: dict = None,
                     content_analysis: dict = None) -> tuple:
    bonus = 0
    bonus_flags = []
    is_whitelisted = (rag_context or {}).get("is_whitelisted", False)
    is_forwarded = spoof.get("is_forwarded", False)

    # Deteksi konten sextortion/pemerasan — jika ada, bonus auth TIDAK berlaku
    has_sextortion = False
    if content_analysis:
        sextortion = content_analysis.get("sextortion", {})
        if sextortion.get("detected") and sextortion.get("count", 0) >= 3:
            has_sextortion = True

    # 🚀 BONUS BARU: Deteksi Template Legitimate via RAG
    # TAPI jangan berikan bonus jika konten mengandung sextortion
    if rag_context and not has_sextortion:
        cat = rag_context.get("highest_match_category", "").lower()
        highest_sim = rag_context.get("highest_similarity", 0)

        if cat == "legitimate" and highest_sim > 0.05: # Minimal 5% kemiripan dengan template aman
            bonus += BONUS_LEGITIMATE_PATTERN
            bonus_flags.append(_bonus_flag(
                f"RAG Deteksi Pola Email Resmi/Legitimate ({highest_sim*100:.1f}% mirip)", BONUS_LEGITIMATE_PATTERN
            ))

    if not is_forwarded:
        auth_all_pass = (
            spoof.get("spf_status") == "pass"
            and spoof.get("dkim_status") == "pass"
            and spoof.get("dmarc_status") == "pass"
        )

        if auth_all_pass:
            # Jika ada sextortion, batalkan bonus auth (sextortion sering dari ISP valid)
            if has_sextortion:
                bonus_flags.append({
                    "key": "auth_bonus_cancelled_sextortion",
                    "category": "BONUS",
                    "label": "Bonus autentikasi DIBATALKAN (Terdeteksi pola ancaman)",
                    "weight": 0
                })
            else:
                bonus += BONUS_AUTH_ALL_PASS
                bonus_flags.append(_bonus_flag(
                    "SPF+DKIM+DMARC semua PASS (autentikasi penuh terverifikasi)", BONUS_AUTH_ALL_PASS
                ))
        elif spoof.get("spf_status") == "pass":
            if not has_sextortion:
                bonus += BONUS_AUTH_PARTIAL
                bonus_flags.append(_bonus_flag(
                    "SPF pass (autentikasi parsial)", BONUS_AUTH_PARTIAL
                ))

        # 🚀 FIX: Whitelist dikabulkan jika TIDAK ADA manipulasi Return-Path ATAU DMARC pass
        # Email via ESP (Mandrill, SendGrid) punya Return-Path berbeda tapi DMARC pass = sah
        if is_whitelisted:
            dmarc_pass = spoof.get("dmarc_status") == "pass"
            if not spoof.get("domain_mismatch") or dmarc_pass:
                bonus += BONUS_WHITELISTED
                bonus_flags.append(_bonus_flag(
                    "Domain pengirim terdaftar di whitelist layanan resmi", BONUS_WHITELISTED
                ))
            else:
                # Berikan informasi kenapa bonus ditolak (transparansi UI)
                bonus_flags.append({
                    "key": "whitelist_bonus_cancelled",
                    "category": "BONUS",
                    "label": "Bonus whitelist DIBATALKAN (Terdeteksi manipulasi Return-Path / Domain Mismatch)",
                    "weight": 0
                })
    else:
        bonus_flags.append({
            "key": "forwarded_bonus_cancelled",
            "category": "BONUS",
            "label": "Bonus legitimasi DIBATALKAN (Autentikasi milik akun penerus, bukan pengirim asli)",
            "weight": 0
        })

    return bonus, bonus_flags


# ──────────────────────────────────────────────
# Flag Transparansi Capping
# ──────────────────────────────────────────────
def _cap_flag(category: str, raw_score: int, capped_score: int) -> dict:
    return {
        "key": f"{category.lower()}_capped",
        "category": category,
        "label": (
            f"Akumulasi skor {category} ({raw_score}) "
            f"poin berada di atas batas normalisasi {capped_score}"
        ),
        "weight": 0,
        "raw_score": raw_score,
        "capped_score": capped_score,
    }


def _total_cap_flag(raw_total: int, final_total: int) -> dict:
    return {
        "key": "total_score_capped",
        "category": "TOTAL",
        "label": (
            f"Nilai skor hasil perhitungan mencapai  {raw_total} "
            f"score melebihi batas sistem "
            f"dengan nilai akhir sistem ditampilkan sebagai {final_total}"
        ),
        "weight": 0,
        "raw_score": raw_total,
        "capped_score": final_total,
    }
# ──────────────────────────────────────────────
# Confidence Level
# ──────────────────────────────────────────────
def _determine_confidence(s_b: int, s_c: int, s_d: int, flags: list) -> dict:
    """
    Tentukan confidence level berdasarkan jenis bukti yang ditemukan.
    """
    high_evidence_keys = {
        "punycode", "cyrillic", "dangerous_ext", "macro_ext",
        "data_uri", "js_uri", "attachment_dangerous", "attachment_macro",
        "double_extension"
    }
    medium_evidence_keys = {
        "deceptive_subdomain", "shortlink", "encoded_auth_fail",
        "link_text_mismatch", "cross_domain_redirect",
        "very_new_domain", "virustotal_high"
    }

    flag_keys = {f.get("key", "") for f in flags}

    has_high = bool(flag_keys & high_evidence_keys)
    has_medium = bool(flag_keys & medium_evidence_keys)

    if has_high:
        return {
            "level": "HIGH",
            "label": "Tinggi",
            "description": "Terdapat bukti teknis kuat (malware/punycode/executable) "
                           "yang mengindikasikan niat jahat.",
        }
    elif has_medium or s_b > 0:
        return {
            "level": "MEDIUM",
            "label": "Sedang",
            "description": "Terdapat indikator teknis yang perlu diwaspadai, "
                           "namun belum cukup untuk konfirmasi definitif.",
        }
    else:
        return {
            "level": "LOW",
            "label": "Rendah",
            "description": "Analisis berdasarkan pola bahasa dan reputasi saja. "
                           "Memerlukan verifikasi lebih lanjut untuk konfirmasi.",
        }

# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
def calculate_score(spoof_analysis: dict,
                    url_analysis: list,
                    domain_info: dict,
                    redirect_results: list,
                    attachment_analysis: dict = None,
                    rag_context: dict = None,
                    content_analysis: dict = None) -> dict:
    """
    Hitung skor risiko secara deterministik (v7.1 Rebalanced).
    S_total = max(min(RAW_S_A + RAW_S_B + RAW_S_C + RAW_S_D + BONUS, 100), 0)
    """

    # ──────────────────────────────────────────────
    # RAW SCORE
    # ──────────────────────────────────────────────
    raw_s_a, f_a = _score_auth(spoof_analysis, rag_context)
    raw_s_b, f_b = _score_urls(
        url_analysis,
        spoof_analysis,
        attachment_analysis
    )
    raw_s_c, f_c = _score_content(
        content_analysis,
        rag_context,
        spoof_analysis
    )
    raw_s_d, f_d = _score_domain_redirect(
        domain_info,
        redirect_results,
        s_b_score=raw_s_b
    )

    # ──────────────────────────────────────────────
    # CATEGORY CAPPING (Hanya untuk Display Breakdown)
    # ──────────────────────────────────────────────
    s_a = min(raw_s_a, CAPS["S_A"])
    s_b = min(raw_s_b, CAPS["S_B"])
    s_c = min(raw_s_c, CAPS["S_C"])
    s_d = min(raw_s_d, CAPS["S_D"])

    # Transparansi capping per kategori
    if raw_s_a > CAPS["S_A"]:
        f_a.append(_cap_flag("S_A", raw_s_a, s_a))

    if raw_s_b > CAPS["S_B"]:
        f_b.append(_cap_flag("S_B", raw_s_b, s_b))

    if raw_s_c > CAPS["S_C"]:
        f_c.append(_cap_flag("S_C", raw_s_c, s_c))

    if raw_s_d > CAPS["S_D"]:
        f_d.append(_cap_flag("S_D", raw_s_d, s_d))

    # ──────────────────────────────────────────────
    # BONUS
    # ──────────────────────────────────────────────
    bonus, bonus_flags = _calculate_bonus(
        spoof_analysis,
        rag_context,
        content_analysis
    )

    # ──────────────────────────────────────────────
    # TOTAL SCORE (Dihitung dari RAW Asli)
    # ──────────────────────────────────────────────
    # Perbaikan Final: Menggunakan raw_s_* murni untuk mempertahankan sisa skor luapan
    raw_total = raw_s_a + raw_s_b + raw_s_c + raw_s_d + bonus

    # Final score dibatasi mentok di 100 (atau minimal 0)
    total = max(min(raw_total, 100), 0)

    # Transparansi total capping
    if raw_total > 100:
        bonus_flags.append(
            _total_cap_flag(raw_total, total)
        )

    # ──────────────────────────────────────────────
    # STATUS
    # ──────────────────────────────────────────────
    if total <= 30:
        status, warna = "AMAN", "green"
    elif total <= 60:
        status, warna = "MENCURIGAKAN", "orange"
    else:
        status, warna = "BERBAHAYA", "red"

    # ──────────────────────────────────────────────
    # FLAGS
    # ──────────────────────────────────────────────
    all_flags = f_a + f_b + f_c + f_d + bonus_flags

    # Confidence level
    confidence = _determine_confidence(
        s_b,
        s_c,
        s_d,
        all_flags
    )

    # ──────────────────────────────────────────────
    # BREAKDOWN
    # ──────────────────────────────────────────────
    breakdown = {
        "S_A": {
            "label": "Autentikasi Email & Header",
            "score": s_a,
            "raw_score": raw_s_a,
            "max": CAPS["S_A"],
            "flags": f_a
        },

        "S_B": {
            "label": "Analisis URL & File (Teknis)",
            "score": s_b,
            "raw_score": raw_s_b,
            "max": CAPS["S_B"],
            "flags": f_b
        },

        "S_C": {
            "label": "Konten & Social Engineering",
            "score": s_c,
            "raw_score": raw_s_c,
            "max": CAPS["S_C"],
            "flags": f_c
        },

        "S_D": {
            "label": "Reputasi Domain & Redirect",
            "score": s_d,
            "raw_score": raw_s_d,
            "max": CAPS["S_D"],
            "flags": f_d
        },
    }

    if bonus_flags:
        breakdown["BONUS"] = {
            "label": "Bonus Legitimasi",
            "score": bonus,
            "max": 0,
            "flags": bonus_flags,
        }

    return {
        "total_score": total,
        "raw_score": raw_total,
        "bonus": bonus,
        "status": status,
        "warna": warna,
        "confidence": confidence,
        "breakdown": breakdown,
        "all_flags": all_flags,
    }