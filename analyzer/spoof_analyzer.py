"""
spoof_analyzer.py v3.5
======================
Perbaikan v3.5 (Forensic Forwarded Email):
- Mampu membaca isi file .eml yang di-encode (Base64/Quoted-Printable).
- Deteksi multi-bahasa & platform: Gmail (EN/ID), Apple Mail, Microsoft Outlook.
- Stripping HTML parsial untuk memastikan regex tidak terpotong tag <b> atau <div>.
- Ekstraksi agresif untuk teks manual/PDF menggunakan Regex.
- Mampu membaca visual header ("From:", "Reply-To:", "X-Mailer:") dari teks copy-paste.
- Fallback ekstrem diperbaiki untuk menangkap email pertama sebagai sender.
- PERBAIKAN AKURASI: Ekstraksi original_sender dipaksa mencari SETELAH penanda forwarded message.
"""

import email
from email.policy import default
import re


# ────────────────────────────────────────────────────────────
# 💡 FUNGSI PENJELASAN AUTENTIKASI UNTUK ORANG AWAM
# ────────────────────────────────────────────────────────────
def _get_auth_explanation(proto: str, status: str) -> str:
    if not status:
        return ""
    s = status.lower()
    if proto == "spf":
        if s == "pass":
            return "Aman. IP server pengirim diizinkan secara resmi oleh pemilik domain."
        elif s == "missing":
            return "Rentan. Domain tidak mengatur daftar server resmi (SPF)."
        else:
            return "BAHAYA! Server yang mengirim email ini TIDAK diakui oleh domain asli."
    elif proto == "dkim":
        if s == "pass":
            return "Aman. Pesan memiliki tanda tangan kriptografi (isinya tidak diubah di jalan)."
        elif s == "missing":
            return "Rentan. Email tidak dilengkapi pelindung tanda tangan digital."
        else:
            return "BAHAYA! Tanda tangan digital rusak atau palsu."
    elif proto == "dmarc":
        if s == "pass":
            return "Aman. Mematuhi kebijakan anti-pemalsuan (anti-spoofing) global."
        elif s == "missing":
            return "Rentan. Domain asli tidak memiliki kebijakan blokir otomatis."
        else:
            return "BAHAYA! Email ini melanggar kebijakan keamanan ketat dari domain asli."
    return ""
# ────────────────────────────────────────────────────────────


def get_root_domain(domain: str) -> str | None:
    if not domain:
        return None
    domain = domain.lower().strip()
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    if parts[-2] in ('co', 'com', 'ac', 'go', 'net', 'org', 'sch', 'or') and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def extract_domain(header_value: str) -> str | None:
    if not header_value:
        return None
    # Ekstrak alamat di dalam < > jika ada
    match = re.search(r'<([^>]+)>', header_value)
    email_address = match.group(1) if match else header_value.strip()
    # Ambil bagian setelah @
    if '@' in email_address:
        return email_address.split('@')[-1].strip().rstrip('>')
    return None


def parse_auth_result(auth_results_header: str) -> dict:
    result = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    if not auth_results_header:
        return result
    text = auth_results_header.lower()
    for proto in ("spf", "dkim", "dmarc"):
        match = re.search(rf'{proto}=(\S+)', text)
        if match:
            val = re.sub(r'[;,\s].*$', '', match.group(1))
            result[proto] = val
    return result


def _parse_received_chain(msg) -> list:
    """
    Parse semua Received headers untuk membangun hop chain.             
    Returns list of dicts dengan server info dan timestamps.
    """
    received_headers = msg.get_all("Received", [])
    chain = []

    for i, header in enumerate(received_headers):
        hop = {
            "index": i + 1,
            "raw": str(header)[:300],
            "from_server": "",
            "by_server": "",
            "protocol": "",
            "suspicious": False,
            "reason": "",
        }

        header_text = str(header)

        # Extract "from" server
        from_match = re.search(r'from\s+(\S+)', header_text, re.IGNORECASE)
        if from_match:
            hop["from_server"] = from_match.group(1).strip("()[]")

        # Extract "by" server
        by_match = re.search(r'by\s+(\S+)', header_text, re.IGNORECASE)
        if by_match:
            hop["by_server"] = by_match.group(1).strip("()[]")

        # Extract protocol
        proto_match = re.search(r'with\s+(E?SMTP\S*)', header_text, re.IGNORECASE)
        if proto_match:
            hop["protocol"] = proto_match.group(1)

        # Deteksi anomali: IP private di public chain
        private_ip = re.search(
            r'(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)',
            header_text
        )
        if private_ip and i < len(received_headers) - 1:
            hop["suspicious"] = True
            hop["reason"] = f"IP Privat Internal ({private_ip.group()}) membocorkan rute ke publik"

        # Deteksi server generik/mencurigakan
        if hop["from_server"]:
            server_lower = hop["from_server"].lower()
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', server_lower):
                hop["suspicious"] = True
                hop["reason"] = "Server menggunakan IP langsung tanpa hostname"
            elif any(s in server_lower for s in ["localhost", "unknown", "[127."]):
                hop["suspicious"] = True
                hop["reason"] = "Hostname mencurigakan (localhost/unknown)"

        chain.append(hop)

    return chain


def _analyze_reply_to(reply_to: str, from_domain: str) -> dict:
    """Analisis Reply-To header untuk mismatch detection."""
    if not reply_to:
        return {
            "reply_to": "",
            "reply_to_domain": "",
            "reply_to_mismatch": False,
        }

    reply_domain = extract_domain(reply_to)
    root_reply = get_root_domain(reply_domain) if reply_domain else None
    root_from = get_root_domain(from_domain) if from_domain else None

    mismatch = bool(root_reply and root_from and root_reply != root_from)

    return {
        "reply_to": reply_to,
        "reply_to_domain": reply_domain or "",
        "reply_to_mismatch": mismatch,
    }


def _analyze_x_mailer(x_mailer: str) -> dict:
    """Analisis X-Mailer header."""
    if not x_mailer:
        return {"x_mailer": "", "suspicious_mailer": False}

    suspicious = False
    mailer_lower = x_mailer.lower()

    # Deteksi tool yang sering digunakan untuk spam/phishing
    suspicious_tools = [
        "phpmailer", "swiftmailer", "mass mailer", "bulk",
        "king", "turbo", "atomic", "group mail", "dark",
    ]
    for tool in suspicious_tools:
        if tool in mailer_lower:
            suspicious = True
            break

    return {
        "x_mailer": x_mailer,
        "suspicious_mailer": suspicious,
    }


def analyze_headers(raw_email_text: str) -> dict:
    # 1. Parsing Standar (Bekerja sempurna untuk file .eml)
    msg = email.message_from_string(raw_email_text, policy=default)

    from_header = msg.get('From', '')
    return_path = msg.get('Return-Path', '')
    auth_results = msg.get('Authentication-Results', '')
    reply_to_header = msg.get('Reply-To', '')
    x_mailer_header = msg.get('X-Mailer', '')
    
    # Ekstrak Subjek Header
    subject_header = msg.get('Subject', '')

    # =====================================================================
    # 2. EKSTRAKSI AGRESIF UNTUK TEKS MANUAL / PDF 
    # =====================================================================
    if not from_header:
        from_match = re.search(r'(?i)^(?:from|sender):\s*(.*)', raw_email_text, re.MULTILINE)
        if from_match:
            from_header = from_match.group(1).strip()

    if not reply_to_header:
        reply_match = re.search(r'(?i)^reply-to:\s*(.*)', raw_email_text, re.MULTILINE)
        if reply_match:
            reply_to_header = reply_match.group(1).strip()

    if not x_mailer_header:
        mailer_match = re.search(r'(?i)^x-mailer:\s*(.*)', raw_email_text, re.MULTILINE)
        if mailer_match:
            x_mailer_header = mailer_match.group(1).strip()
            
    if not subject_header:
        subj_match = re.search(r'(?i)^subject:\s*(.*)', raw_email_text, re.MULTILINE)
        if subj_match:
            subject_header = subj_match.group(1).strip()

    # FALLBACK EKSTREM
    if not from_header:
        fallback_match = re.search(
            r'<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>'
            r'|([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            raw_email_text
        )
        if fallback_match:
            from_header = fallback_match.group(1) or fallback_match.group(2)

    if not return_path and from_header:
        return_path = from_header
    # =====================================================================

    from_domain = extract_domain(from_header)
    return_domain = extract_domain(return_path)
    root_from = get_root_domain(from_domain)
    root_return = get_root_domain(return_domain)

    domain_mismatch = bool(root_from and root_return and root_from != root_return)
    parsed = parse_auth_result(auth_results)

    spf_status = parsed["spf"]
    spf_fail = spf_status not in ("pass", "neutral", "missing")
    dkim_status = parsed["dkim"]
    dkim_fail = dkim_status not in ("pass", "missing")
    dmarc_status = parsed["dmarc"]
    dmarc_fail = dmarc_status not in ("pass", "missing")

    all_missing = (
        spf_status == "missing"
        and dkim_status == "missing"
        and dmarc_status == "missing"
    )

    received_chain = _parse_received_chain(msg)
    suspicious_hops = [h for h in received_chain if h["suspicious"]]

    reply_to_info = _analyze_reply_to(reply_to_header, from_domain)
    x_mailer_info = _analyze_x_mailer(x_mailer_header)

    # Status autentikasi
    if spf_fail or dkim_fail or dmarc_fail:
        auth_summary = "GAGAL AUTENTIKASI / PALSU"
        auth_class = "text-danger"
    elif all_missing:
        auth_summary = "TIDAK ADA AUTENTIKASI (RENTAN)"
        auth_class = "text-warning"
    elif dmarc_status == "missing" or dkim_status == "missing":
        auth_summary = "AUTENTIKASI LEMAH (Tanpa DKIM/DMARC)"
        auth_class = "text-warning"
    else:
        auth_summary = "VALID & AMAN"
        auth_class = "text-success"

    # DETEKSI EMAIL FORWARDED & EKSTRAKSI PENGIRIM ASLI (FORENSIK)

    is_forwarded = False
    forward_indicators = []
    original_sender = None
    original_domain = None

    # 1. Dekode isi pesan agar bisa dibaca Regex
    decoded_body = raw_email_text
    if msg.is_multipart() or msg.get_payload():
        try:
            parts = []
            for part in msg.walk():
                if part.get_content_type() in ['text/plain', 'text/html'] and not str(part.get('Content-Disposition')).startswith('attachment'):
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode('utf-8', errors='ignore'))
            if parts:
                decoded_body = "\n".join(parts)
        except Exception:
            pass
    
    # 2. Bersihkan HTML tags sedikit agar regex teks murni tidak terhalang tag
    decoded_body_clean = re.sub(r'<[^>]+>', ' ', decoded_body)

    # 3. Deteksi Pola Multi-Bahasa dan Platform (Gmail ID/EN, Outlook, Apple Mail)
    is_fwd_subject = re.search(r'(?i)^(fwd?|fw|terusan|diteruskan)\s*:', subject_header) if subject_header else False
    
    # Pola marker body email terusan
    marker_pattern = r'(?i)(?:-+\s*(?:Forwarded message|Pesan terusan|Pesan yang diteruskan|Original Message)\s*-+)|(?:(?:Begin forwarded message|Awal pesan terusan):)'
    
    is_fwd_body = re.search(marker_pattern, decoded_body_clean)
    is_fwd_header = msg.get("Resent-From") or msg.get("X-Forwarded-To")

    if is_fwd_subject or is_fwd_body or is_fwd_header:
        is_forwarded = True
        
        # Temukan lokasi letak pemisah di body yang sudah di-decode
        fwd_marker = re.search(marker_pattern, decoded_body_clean)
        
        if fwd_marker:
            text_to_search = decoded_body_clean[fwd_marker.end():]
        else:
            text_to_search = decoded_body_clean
            
        # 4. Cari email pengirim asli setelah marker
        orig_from_match = re.search(r'(?i)(?:From|Dari):\s*.*?(?:<)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text_to_search)
        
        if orig_from_match:
            original_sender = orig_from_match.group(1).strip()
            original_domain = original_sender.split('@')[-1]
            forward_indicators.append(f"Pengirim Asli (Forensik): {original_sender}")
        else:
            # Fallback ekstrim: cari email apapun setelah penanda forward jika pola From/Dari rusak
            fallback_orig = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text_to_search)
            if fallback_orig:
                 original_sender = fallback_orig.group(1).strip()
                 original_domain = original_sender.split('@')[-1]
                 forward_indicators.append(f"Pengirim Asli (Forensik via Fallback): {original_sender}")
            else:
                 original_sender = "Gagal mengekstrak pengirim asli"
                 forward_indicators.append("Format pengirim tidak dikenali di dalam body")

        # Abaikan jika sender asli sama dengan penerus (User forward email miliknya sendiri)
        if original_sender and from_header and original_sender.lower() in from_header.lower():
            is_forwarded = False
            forward_indicators = []
    # =====================================================================

    return {
        "from_header":      from_header or "Tidak Ditemukan",
        "return_path":      return_path or "Tidak Ditemukan",
        "auth_results":     auth_results or "Tidak ada protokol terdeteksi (Teks/PDF Bebas)",
        "from_domain":      from_domain or "-",
        "return_domain":    return_domain or "-",
        "root_from":        root_from or "-",
        "root_return":      root_return or "-",
        "domain_mismatch":  domain_mismatch,
        
        "spf_status":       spf_status,
        "spf_explanation":  _get_auth_explanation("spf", spf_status),
        "spf_fail":         spf_fail,
        
        "dkim_status":      dkim_status,
        "dkim_explanation": _get_auth_explanation("dkim", dkim_status),
        "dkim_fail":        dkim_fail,
        
        "dmarc_status":     dmarc_status,
        "dmarc_explanation":_get_auth_explanation("dmarc", dmarc_status),
        "dmarc_fail":       dmarc_fail,
        
        "spf_missing":      spf_status == "missing",
        "dkim_missing":     dkim_status == "missing",
        "dmarc_missing":    dmarc_status == "missing",
        "all_auth_missing": all_missing,
        "auth_summary":     auth_summary,
        "auth_class":       auth_class,
        
        "received_chain":     received_chain,
        "received_hop_count": len(received_chain),
        "suspicious_hops":    suspicious_hops,
        "has_suspicious_hops": len(suspicious_hops) > 0,
        
        "subject_header":     subject_header or "Tidak Ada Subjek",
        "is_forwarded":       is_forwarded,
        "forward_indicators": forward_indicators,
        "original_sender":    original_sender,
        "original_domain":    original_domain,
        
        **reply_to_info,
        **x_mailer_info,
    }