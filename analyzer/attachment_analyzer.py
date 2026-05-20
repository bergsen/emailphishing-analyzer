
import email
from email.policy import default as default_policy
import re
import hashlib
import zipfile
import io

# ──────────────────────────────────────────────
# Konstanta
# ──────────────────────────────────────────────

DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psc1',
    '.msi', '.msp', '.jar', '.com', '.pif', '.cpl',
    '.apk', '.dmg', '.iso', '.img', '.hta', '.inf',
    '.reg', '.rgs', '.sct', '.shb', '.shs', '.lnk',
}

MACRO_EXTENSIONS = {
    '.xlsm', '.docm', '.pptm', '.xlsb',
    '.xltm', '.dotm', '.xlam', '.ppam',
    '.xla', '.dot',
}

ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.cab', '.arj', '.ace',
}

SUSPICIOUS_CONTENT_TYPES = {
    'application/x-msdownload',
    'application/x-executable',
    'application/x-dosexec',
    'application/hta',
    'application/x-msi',
    'application/java-archive',
}

DOUBLE_EXT_PATTERN = re.compile(
    r'\.\w{2,5}\.(exe|scr|bat|cmd|vbs|js|ps1|msi|jar|apk|hta|com|pif|lnk)$',
    re.IGNORECASE
)

URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>()]+',
    re.IGNORECASE
)

SUSPICIOUS_PDF_KEYWORDS = {
    "login",
    "verify",
    "password",
    "security",
    "account",
    "payment",
    "invoice",
    "update",
    "microsoft",
    "office365",
}

SUSPICIOUS_UNICODE = {
    '\u202e',
    '\u202d',
    '\u200f',
}

MAGIC_SIGNATURES = {
    b'MZ': 'exe',
    b'%PDF': 'pdf',
    b'PK': 'zip',
}

EXPECTED_MIME = {
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
    '.exe': 'application/x-msdownload',
}

# ──────────────────────────────────────────────
# Main Analyzer
# ──────────────────────────────────────────────

def analyze_attachments(raw_email_text: str) -> dict:

    result = {
        "attachments": [],
        "total_count": 0,
        "dangerous_count": 0,
        "macro_count": 0,
        "archive_count": 0,
        "suspicious_count": 0,
        "has_dangerous": False,
        "has_macro": False,
        "has_double_extension": False,
        "risk_summary": "RENDAH",
    }

    try:
        msg = email.message_from_string(
            raw_email_text,
            policy=default_policy
        )

    except Exception:
        return result

    for part in msg.walk():

        content_disposition = str(
            part.get("Content-Disposition", "")
        )

        content_type = (
            part.get_content_type() or ""
        ).lower()

        filename = part.get_filename()

        if not filename and "attachment" not in content_disposition.lower():
            continue

        if not filename:
            filename = "unnamed_attachment"

        filename_lower = filename.lower()

        # Extension
        ext = ""
        dot_pos = filename_lower.rfind(".")

        if dot_pos >= 0:
            ext = filename_lower[dot_pos:]

        # Payload
        payload = part.get_payload(decode=True)

        size = len(payload) if payload else 0

        # Hash
        file_hash = ""

        if payload:
            file_hash = hashlib.sha256(
                payload
            ).hexdigest()[:16]

        # ──────────────────────────────────────────────
        # Existing Detection
        # ──────────────────────────────────────────────

        is_dangerous = ext in DANGEROUS_EXTENSIONS
        is_macro = ext in MACRO_EXTENSIONS
        is_archive = ext in ARCHIVE_EXTENSIONS

        is_suspicious_type = (
            content_type.lower()
            in SUSPICIOUS_CONTENT_TYPES
        )

        has_double_ext = bool(
            DOUBLE_EXT_PATTERN.search(
                filename_lower
            )
        )

        # ──────────────────────────────────────────────
        # Additional Detection
        # ──────────────────────────────────────────────

        risk_score = 0

        # Magic signature validation
        detected_signature = "unknown"

        if payload:
            for sig, sig_name in MAGIC_SIGNATURES.items():
                if payload.startswith(sig):
                    detected_signature = sig_name
                    break

        # MIME mismatch
        mime_mismatch = False

        expected_mime = EXPECTED_MIME.get(ext)

        if expected_mime:
            if expected_mime not in content_type:
                mime_mismatch = True

        # Unicode spoofing
        has_unicode_spoofing = any(
            char in filename
            for char in SUSPICIOUS_UNICODE
        )

        # PDF inspection
        pdf_urls = []
        pdf_suspicious_keywords = []
        pdf_has_javascript = False
        pdf_has_openaction = False
        pdf_has_embedded_file = False

        if ext == ".pdf" and payload:

            try:
                pdf_text = payload.decode(
                    errors="ignore"
                ).lower()

                # Extract URLs
                pdf_urls = URL_PATTERN.findall(
                    pdf_text
                )[:20]

                # Suspicious keywords
                for keyword in SUSPICIOUS_PDF_KEYWORDS:
                    if keyword in pdf_text:
                        pdf_suspicious_keywords.append(
                            keyword
                        )

                # PDF Indicators
                if "/javascript" in pdf_text:
                    pdf_has_javascript = True

                if "/openaction" in pdf_text:
                    pdf_has_openaction = True

                if "/embeddedfile" in pdf_text:
                    pdf_has_embedded_file = True

            except Exception:
                pass

        # Archive inspection
        archive_contains_dangerous = False
        archive_file_list = []

        if ext == ".zip" and payload:

            try:
                with zipfile.ZipFile(
                    io.BytesIO(payload)
                ) as zf:

                    archive_file_list = zf.namelist()

                    for inner_file in archive_file_list:

                        inner_lower = inner_file.lower()

                        for bad_ext in DANGEROUS_EXTENSIONS:
                            if inner_lower.endswith(bad_ext):
                                archive_contains_dangerous = True
                                break

            except Exception:
                pass

        # ──────────────────────────────────────────────
        # Risk Assessment
        # ──────────────────────────────────────────────

        risk_level = "RENDAH"
        risk_reasons = []

        # Existing Logic
        if is_dangerous or has_double_ext:

            risk_level = "TINGGI"

            if is_dangerous:
                risk_reasons.append(
                    f"Ekstensi berbahaya ({ext})"
                )
                risk_score += 50

            if has_double_ext:
                risk_reasons.append(
                    "Double extension terdeteksi"
                )
                risk_score += 40

        elif is_macro:

            risk_level = "TINGGI"

            risk_reasons.append(
                f"File bermakro ({ext})"
            )

            risk_score += 45

        elif is_suspicious_type:

            risk_level = "SEDANG"

            risk_reasons.append(
                f"Content-type mencurigakan ({content_type})"
            )

            risk_score += 25

        elif is_archive:

            risk_level = "SEDANG"

            risk_reasons.append(
                f"File arsip ({ext}) — bisa menyembunyikan malware"
            )

            risk_score += 15

        # Additional Risk Logic

        if mime_mismatch:

            risk_reasons.append(
                "MIME type tidak sesuai extension"
            )

            risk_score += 35

        if has_unicode_spoofing:

            risk_reasons.append(
                "Unicode spoofing filename"
            )

            risk_score += 30

        if detected_signature == "exe" and ext != ".exe":

            risk_reasons.append(
                "Signature executable tersembunyi"
            )

            risk_score += 50

        # PDF Risk
        if pdf_urls:

            risk_reasons.append(
                f"PDF mengandung URL ({len(pdf_urls)})"
            )

            risk_score += min(
                len(pdf_urls) * 5,
                25
            )

        if pdf_suspicious_keywords:

            risk_reasons.append(
                "Keyword phishing ditemukan dalam PDF"
            )

            risk_score += 20

        if pdf_has_javascript:

            risk_reasons.append(
                "PDF JavaScript terdeteksi"
            )

            risk_score += 40

        if pdf_has_openaction:

            risk_reasons.append(
                "PDF OpenAction terdeteksi"
            )

            risk_score += 35

        if pdf_has_embedded_file:

            risk_reasons.append(
                "PDF EmbeddedFile terdeteksi"
            )

            risk_score += 45

        # Archive Risk
        if archive_contains_dangerous:

            risk_reasons.append(
                "ZIP mengandung file berbahaya"
            )

            risk_score += 50

        # Final Risk Classification
        if risk_score >= 70:
            risk_level = "TINGGI"

        elif risk_score >= 30:
            risk_level = "SEDANG"

        else:
            risk_level = "RENDAH"

        # ──────────────────────────────────────────────
        # Attachment Info
        # ──────────────────────────────────────────────

        attachment_info = {
            "filename": filename,
            "extension": ext or "-",
            "content_type": content_type,
            "size_bytes": size,
            "size_display": _format_size(size),
            "hash_sha256_short": file_hash,

            # Existing
            "is_dangerous": is_dangerous,
            "is_macro": is_macro,
            "is_archive": is_archive,
            "has_double_extension": has_double_ext,

            # New
            "risk_score": risk_score,
            "detected_signature": detected_signature,
            "mime_mismatch": mime_mismatch,
            "has_unicode_spoofing": has_unicode_spoofing,

            # PDF
            "pdf_url_count": len(pdf_urls),
            "pdf_has_javascript": pdf_has_javascript,
            "pdf_has_openaction": pdf_has_openaction,
            "pdf_has_embedded_file": pdf_has_embedded_file,

            # Archive
            "archive_contains_dangerous": archive_contains_dangerous,
            "archive_file_count": len(archive_file_list),

            # Risk
            "risk_level": risk_level,
            "risk_reasons": risk_reasons,
        }

        result["attachments"].append(
            attachment_info
        )

        # Existing Counters
        if is_dangerous or has_double_ext:
            result["dangerous_count"] += 1

        if is_macro:
            result["macro_count"] += 1

        if is_archive:
            result["archive_count"] += 1

        if (
            is_suspicious_type
            or mime_mismatch
            or pdf_has_javascript
            or archive_contains_dangerous
        ):
            result["suspicious_count"] += 1

    # ──────────────────────────────────────────────
    # Final Summary
    # ──────────────────────────────────────────────

    result["total_count"] = len(
        result["attachments"]
    )

    result["has_dangerous"] = (
        result["dangerous_count"] > 0
    )

    result["has_macro"] = (
        result["macro_count"] > 0
    )

    result["has_double_extension"] = any(
        a["has_double_extension"]
        for a in result["attachments"]
    )

    # Overall Risk
    if (
        result["has_dangerous"]
        or result["has_double_extension"]
    ):
        result["risk_summary"] = "TINGGI"

    elif result["has_macro"]:
        result["risk_summary"] = "TINGGI"

    elif (
        result["suspicious_count"] > 0
        or result["archive_count"] > 0
    ):
        result["risk_summary"] = "SEDANG"

    return result


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _format_size(size_bytes: int) -> str:

    if size_bytes < 1024:
        return f"{size_bytes} B"

    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"

    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"