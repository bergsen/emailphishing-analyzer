import re
import os
import html as html_lib
import email
from email.policy import default as default_policy

from flask import Flask, render_template, request
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

from analyzer.url_analyzer import analyze_urls, extract_urls_from_text
from analyzer.redirect_trace import trace_all_redirects
from analyzer.domain_reputation import get_all_domain_info
from analyzer.spoof_analyzer import analyze_headers
from analyzer.scoring_engine import calculate_score
from analyzer.llm_evaluator import generate_narrative
from analyzer.content_analyzer import analyze_content
from analyzer.attachment_analyzer import analyze_attachments
from analyzer.rag_engine import build_rag_context, compute_tfidf_details

# ──────────────────────────────────────────────
# In-memory store untuk data TF-IDF terakhir
# ──────────────────────────────────────────────
_last_analysis = {
    "email_text": None, 
    "tfidf_data": None,
    "llm_reasoning": None
}

# ──────────────────────────────────────────────
# App Configuration
# ──────────────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB max upload
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", os.urandom(32).hex())

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60 per hour", "10 per minute"],
    storage_uri="memory://",
)

def _sanitize_text(text: str) -> str:
    """Sanitize input text untuk mencegah XSS."""
    return html_lib.escape(text)

# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
@limiter.limit("5 per minute")
def analyze():
    email_text = ""
    file_name = "Teks Input Manual"

    # ── 1. Input Handling (.eml / .txt / .pdf) ──
    if 'email_file' in request.files and request.files['email_file'].filename:
        file = request.files['email_file']
        filename_raw = file.filename.lower()
        file_name = file.filename

        if filename_raw.endswith('.pdf'):
            try:
                from pypdf import PdfReader
                reader = PdfReader(file)
                for page in reader.pages:
                    extracted = page.extract_text()
                    if extracted:
                        email_text += extracted + "\n"
            except Exception:
                return "Gagal membaca file PDF.", 400
        else:
            # Otomatis baca format .eml atau .txt sebagai raw string
            email_text = file.read().decode('utf-8', errors='ignore')
    else:
        email_text = request.form.get("email_text", "")

    if not email_text.strip():
        return "Tidak ada input email yang ditemukan.", 400

    if len(email_text) > 500_000:
        email_text = email_text[:500_000]

    # Bersihkan memori sesi lama
    _last_analysis["email_text"] = email_text[:50000]
    _last_analysis["tfidf_data"] = None
    _last_analysis["llm_reasoning"] = None

    # ── 2. Analisis Komponen ──
    spoof_analysis = analyze_headers(email_text)
    urls = extract_urls_from_text(email_text)
    url_analysis = analyze_urls(urls)

    redirect_results = trace_all_redirects(urls, max_urls=5) if urls else []

    domain_info = get_all_domain_info(urls, max_domains=5) if urls else {
        "all_results": [], "primary": {},
        "total_vt_positives": 0, "max_vt_positives": 0,
        "has_abuseipdb_hit": False, "max_abuseipdb_score": 0,
        "has_urlscan_malicious": False,
    }

    content_analysis = analyze_content(email_text)
    attachment_analysis = analyze_attachments(email_text)
    rag_context = build_rag_context(email_text, spoof_analysis)

    # ── 3. Pembersihan EML (MIME Parsing) & Preview Rapi ──
    try:
        msg = email.message_from_string(email_text, policy=default_policy)
        headers_to_show = []
        for h in ['From', 'To', 'Subject', 'Date']:
            val = msg.get(h)
            if val:
                headers_to_show.append(f"{h}: {val}")
        
        html_part = ""
        text_part = ""

        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get_content_disposition() in ['attachment', 'inline']:
                continue
                
            content_type = part.get_content_type()
            
            if content_type == 'text/html':
                try: 
                    html_part += part.get_content() + "\n"
                except: 
                    payload = part.get_payload(decode=True)
                    if payload: html_part += payload.decode('utf-8', errors='ignore') + "\n"
            
            elif content_type == 'text/plain':
                try: 
                    text_part += part.get_content() + "\n"
                except: 
                    payload = part.get_payload(decode=True)
                    if payload: text_part += payload.decode('utf-8', errors='ignore') + "\n"

        if not html_part and "<html" in email_text.lower():
            html_part = email_text
        if not text_part:
            text_part = email_text 

        header_string = "\n".join(headers_to_show)
        raw_text_view = header_string + "\n\n" + text_part.strip()

        if html_part.strip():
            html_header_box = f"<div style='background:#f4f4f4; padding:15px; margin-bottom:10px; border-bottom:2px solid #ddd; font-family:sans-serif; font-size:13px; color:#333;'><pre style='margin:0; white-space:pre-wrap;'>{html_lib.escape(header_string)}</pre></div>"
            html_view = html_header_box + html_part
        else:
            html_view = f"<pre style='padding:15px; font-family:sans-serif;'>{html_lib.escape(raw_text_view)}</pre>"

    except Exception:
        raw_text_view = email_text
        html_view = f"<pre style='padding:15px; font-family:sans-serif;'>{html_lib.escape(email_text)}</pre>"

    # ── 4. Highlight Indikator (Hanya di Plain Text) ──
    safe_preview = _sanitize_text(raw_text_view[:5000])
    if len(raw_text_view) > 5000:
        safe_preview += "\n\n[... Teks dipotong karena terlalu panjang ...]"

    if rag_context and rag_context.get("se_tactics"):
        red_words, yellow_words = [], []
        for tactic_info in rag_context["se_tactics"]:
            tactic = tactic_info["tactic"]
            matches = tactic_info["matched_keywords"]
            if tactic in ['fear', 'credential_request', 'authority']:
                red_words.extend(matches)
            elif tactic in ['urgency', 'reward', 'secrecy']:
                yellow_words.extend(matches)

        red_words = sorted(list(set([w for w in red_words if w])), key=len, reverse=True)
        yellow_words = sorted(list(set([w for w in yellow_words if w])), key=len, reverse=True)

        if red_words:
            pattern_red = re.compile(r'(?i)(' + '|'.join(map(re.escape, red_words)) + r')')
            safe_preview = pattern_red.sub(r'<span style="background-color: rgba(251, 113, 133, 0.2); color: var(--neon-red); font-weight: bold; padding: 2px 4px; border-radius: 4px;">\1</span>', safe_preview)

        if yellow_words:
            pattern_yellow = re.compile(r'(?i)(' + '|'.join(map(re.escape, yellow_words)) + r')')
            safe_preview = pattern_yellow.sub(r'<span style="background-color: rgba(250, 204, 21, 0.2); color: var(--neon-yellow); font-weight: bold; padding: 2px 4px; border-radius: 4px;">\1</span>', safe_preview)

    safe_preview = safe_preview.replace('\n', '<br>')

    email_preview = {
        "text_content": safe_preview,
        "html_content": html_view
    }
    file_info = {"name": _sanitize_text(file_name)}

    # ── 5. Scoring & LLM (Hanya 1x Call API) ──
    score_result = calculate_score(
        spoof_analysis=spoof_analysis,
        url_analysis=url_analysis,
        domain_info=domain_info,
        redirect_results=redirect_results,
        attachment_analysis=attachment_analysis,
        rag_context=rag_context,
        content_analysis=content_analysis,
    )

    # =====================================================================
    # 🚀 BLOK INTERSEPSI UNTUK INPUT TEKS MANUAL / PDF (SINKRONISASI RAG)
    # =====================================================================
    # Jika tidak ada header autentikasi sama sekali (biasanya karena input PDF/teks manual)
    # CATATAN: Blok ini TIDAK berlaku untuk input raw email (.eml) yang memiliki header
    if spoof_analysis.get("all_auth_missing"):
        s_c_score = score_result.get("breakdown", {}).get("S_C", {}).get("score", 0)

        # Ekstrak data krusial dari RAG Engine
        rag_sim = rag_context.get("highest_similarity", 0) if rag_context else 0
        rag_category = rag_context.get("highest_match_category", "").lower() if rag_context else "unknown"
        rag_risk_level = rag_context.get("rag_risk_level", "RENDAH") if rag_context else "RENDAH"

        # ── PENGECUALIAN DISCLAIMER RESMI (DIPERLUAS HINGGA ~60+ FRASA) ──
        teks_lower = email_text.lower()

        disclaimers = [
            # Perbankan & Finansial
            "tidak pernah meminta", "jangan pernah memberitahukan", "abaikan email ini", "call center",
            "hubungi kami", "hubungi customer service", "terima kasih atas pembayaran", "transaksi anda telah",
            "pesanan anda telah", "syarat dan ketentuan", "terima kasih telah menggunakan", "bukti transaksi",
            "informasi saldo", "rekening anda", "nasabah yth", "dear customer", "payment confirmation",
            "transaction successful", "bank tidak pernah", "pin anda", "kode otp", "jangan bagikan kode ini",
            "customer care", "layanan pelanggan", "contact center", "cabang terdekat", "penyesuaian biaya",

            # Keamanan & Sistem
            "login baru", "sandi anda diubah", "periksa aktivitas", "jika ini memang anda, anda tidak perlu melakukan apa-apa",
            "kami menemukan adanya login baru", "aktivitas login mencurigakan", "kode keamanan", "keamanan akun",
            "security alert", "new login", "password changed", "verify your account", "two-factor authentication",
            "jika anda tidak melakukan", "if you did not request", "was this you", "reset password", "lupa kata sandi",
            "no action required", "abaikan pesan ini",

            # E-commerce & Shopping
            "berhenti berlangganan", "unsubscribe", "no action needed", "no action is needed",
            "if you did not", "if you didn't", "terms and conditions", "contact us", "privacy policy",
            "kebijakan privasi", "hak cipta dilindungi", "all rights reserved", "order confirmation",
            "shipping update", "delivery status", "lacak pesanan", "track your order", "faktur pembelian",
            "invoice details", "nomor resi", "dikirim oleh", "delivered by",

            # Corporate, HR & Umum
            "harap jangan membalas", "do not reply", "email otomatis", "automated email", "surat ini dibuat otomatis",
            "this is an automated message", "departemen sdm", "human resources", "undangan meeting", "meeting invitation",
            "jadwal wawancara", "interview schedule", "pengumuman perusahaan", "company announcement", "kepada yth",
            "hormat kami", "best regards", "sincerely yours"
        ]

        # Hitung kemunculan frasa legitimate
        legit_phrase_count = sum(1 for phrase in disclaimers if phrase in teks_lower)

        # Counter-check baru: batalkan jika frasa legitimate >= 3
        is_disclaimer = legit_phrase_count >= 3

        # ── SINKRONISASI RAG: Validasi Kategori Ancaman ──
        # Jangan jatuhkan penalti jika RAG mengklasifikasikan pola sebagai "safe" atau "legitimate"
        is_rag_phishing = rag_sim > 0.12 and rag_category not in ["safe", "legitimate", "unknown", "informative"]
        is_rag_legitimate = rag_category in ["legitimate", "safe"] and rag_sim > 0.12

        # ── BONUS LEGITIMASI TF-IDF (-10): Jika RAG mendeteksi pola legit ──
        if is_rag_legitimate or is_disclaimer:
            bonus_legit = -10
            score_result["total_score"] = max(score_result["total_score"] + bonus_legit, 1)
            score_result["raw_score"] = score_result["total_score"]

            rag_sim_pct = round(rag_sim * 100, 1)
            flag_bonus_legit = {
                "key": "manual_text_legit_bonus",
                "category": "BONUS",
                "label": f"Bonus TF-IDF Legitimate: Pola teks cocok dengan template email resmi",
                "weight": bonus_legit
            }

            if "BONUS" not in score_result["breakdown"]:
                score_result["breakdown"]["BONUS"] = {
                    "label": "Bonus Legitimasi",
                    "score": 0,
                    "max": 0,
                    "flags": []
                }

            score_result["breakdown"]["BONUS"]["score"] += bonus_legit
            score_result["breakdown"]["BONUS"]["flags"].append(flag_bonus_legit)
            score_result["all_flags"].append(flag_bonus_legit)

            # Recalculate status
            if score_result["total_score"] <= 30:
                score_result["status"], score_result["warna"] = "AMAN", "green"
            elif score_result["total_score"] <= 60:
                score_result["status"], score_result["warna"] = "MENCURIGAKAN", "orange"
            else:
                score_result["status"], score_result["warna"] = "BERBAHAYA", "red"

        # ── PENALTI PHISHING TF-IDF (+20): Jika RAG konfirmasi pola ancaman ──
        elif (s_c_score >= 4 or is_rag_phishing) and not is_disclaimer:
            injeksi_skor = 20  # Suntik poin penalti

            score_result["total_score"] = min(score_result["total_score"] + injeksi_skor, 100)
            score_result["raw_score"] = score_result["total_score"]

            # Recalculate status
            if score_result["total_score"] <= 30:
                score_result["status"], score_result["warna"] = "AMAN", "green"
            elif score_result["total_score"] <= 60:
                score_result["status"], score_result["warna"] = "MENCURIGAKAN", "orange"
            else:
                score_result["status"], score_result["warna"] = "BERBAHAYA", "red"

            # Format persentase RAG untuk ditampilkan di label
            rag_sim_pct = round(rag_sim * 100, 1)
            kategori_rag = rag_category.upper() if rag_category != "unknown" else "PHISHING"

            flag_tambahan = {
                "key": "manual_text_penalty",
                "category": "PENALTI",
                "label": f"Penalti TF-IDF Phishing: teks disinkronkan dengan Database RAG ({rag_sim_pct}% mirip pola {kategori_rag})",
                "weight": injeksi_skor
            }

            if "PENALTI" not in score_result["breakdown"]:
                score_result["breakdown"]["PENALTI"] = {
                    "label": "Tindakan Defensif Input Manual",
                    "score": 0,
                    "max": 25,
                    "flags": []
                }

            score_result["breakdown"]["PENALTI"]["score"] += injeksi_skor
            score_result["breakdown"]["PENALTI"]["flags"].append(flag_tambahan)
            score_result["all_flags"].append(flag_tambahan)

        # ── PENALTI BARU: JIKA URL KOSONG (Antisipas) ──
        if len(urls) == 0:
            penalti_url_kosong = 5
            score_result["total_score"] = min(score_result["total_score"] + penalti_url_kosong, 100)
            score_result["raw_score"] = score_result["total_score"]

            flag_url_kosong = {
                "key": "no_url_penalty",
                "category": "PENALTI",
                "label": "Teks/PDF Tidak Memiliki URL Terlacak (Potensi Ancaman)",
                "weight": penalti_url_kosong
            }

            if "PENALTI" not in score_result["breakdown"]:
                score_result["breakdown"]["PENALTI"] = {
                    "label": "Tindakan Defensif Input Manual",
                    "score": 0,
                    "max": 25,
                    "flags": []
                }
            else:
                score_result["breakdown"]["PENALTI"]["max"] = 25

            score_result["breakdown"]["PENALTI"]["score"] += penalti_url_kosong
            score_result["breakdown"]["PENALTI"]["flags"].append(flag_url_kosong)
            score_result["all_flags"].append(flag_url_kosong)

            # Recalculate status lagi setelah pengurangan poin tambahan
            if score_result["total_score"] <= 30:
                score_result["status"], score_result["warna"] = "AMAN", "green"
            elif score_result["total_score"] <= 60:
                score_result["status"], score_result["warna"] = "MENCURIGAKAN", "orange"
            else:
                score_result["status"], score_result["warna"] = "BERBAHAYA", "red"

    # =====================================================================

    # LLM sekarang akan menerima `score_result` yang sudah disuntik (jika terkena penalti)
    narrative = generate_narrative(
        email_text=email_text,
        score_result=score_result,
        spoof_analysis=spoof_analysis,
        url_analysis=url_analysis,
        domain_info=domain_info,
        rag_context=rag_context,
        content_analysis=content_analysis,
        attachment_analysis=attachment_analysis,
    )

    # Simpan hasil narasi semantik RAG dari LLM ke memori lokal untuk UI tfidf.html
    _last_analysis["llm_reasoning"] = narrative.get("analisis_semantik_rag", "")

    risk_details = {
        "score": score_result["total_score"],
        "raw_score": score_result.get("raw_score", score_result["total_score"]),
        "bonus": score_result.get("bonus", 0),
        "status": score_result["status"],
        "warna": score_result["warna"],
        "saran": narrative["saran"],
        "rincian": narrative["rincian"],
        "breakdown": score_result["breakdown"],
        "all_flags": score_result["all_flags"],
    }

    primary_domain = domain_info.get("primary", {})

    # Simpan semua data untuk halaman PDF/cetak
    template_data = dict(
        urls=urls,
        url_analysis=url_analysis,
        redirect_chain=[],
        redirect_results=redirect_results,
        domain_info=primary_domain,
        all_domain_info=domain_info.get("all_results", []),
        spoof_analysis=spoof_analysis,
        risk_details=risk_details,
        email_preview=email_preview,
        file_info=file_info,
        content_analysis=content_analysis,
        attachment_analysis=attachment_analysis,
        rag_context=rag_context,
    )
    _last_analysis["full_data"] = template_data

    return render_template("result.html", **template_data)

# ──────────────────────────────────────────────
# ROUTE BARU: HALAMAN KHUSUS PDF/CETAK
# ──────────────────────────────────────────────
@app.route("/halaman_pdf", methods=["GET"])
def halaman_pdf():
    full_data = _last_analysis.get("full_data")
    if not full_data:
        return "Tidak ada data. Silakan kembali ke halaman utama dan analisa email ulang.", 400
    
    # Kita render template laporan forensik khusus (hitam putih, formal)
    return render_template("laporan_forensik.html", **full_data)

@app.route("/tfidf", methods=["GET"])
def tfidf_page():
    email_text = _last_analysis.get("email_text")
    if not email_text:
        return render_template("tfidf.html", tfidf_data=None, has_data=False)

    if _last_analysis.get("tfidf_data") is None:
        _last_analysis["tfidf_data"] = compute_tfidf_details(email_text)

    # Ambil hasil penalaran LLM yang sudah digenerate dari halaman utama
    llm_reasoning = _last_analysis.get("llm_reasoning")

    return render_template(
        "tfidf.html", 
        tfidf_data=_last_analysis["tfidf_data"], 
        has_data=True,
        llm_reasoning=llm_reasoning
    )

@app.errorhandler(413)
def too_large(e):
    return "File terlalu besar. Maksimum 10 MB.", 413

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return "Terlalu banyak permintaan. Silakan coba lagi nanti.", 429

@app.errorhandler(500)
def internal_error(e):
    return "Terjadi kesalahan internal. Silakan coba lagi.", 500

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=3000)