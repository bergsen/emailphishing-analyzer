"""
rag_engine.py v12.1 — RAG Engine (Pure TF-IDF with Deep Sanitization)
====================================================================================
ARSITEKTUR MURNI & ANTI-NOISE:
- EML Parser: Mendukung ekstraksi text/plain dan text/html secara sempurna.
- Anti-Base64: Membuang kata > 20 karakter untuk mencegah hash & base64 masuk vektor.
- MIME & SMTP Stopwords: Membasmi "contenttype", "smtp", "deliveredto", dll.
- TANPA INJEKSI PAKSA: TF-IDF murni statistik namun dengan data yang higienis!
- N-GRAM: Mendukung Unigram (1 kata) dan Bigram (2 kata) sekaligus untuk konteks maksimal.
"""

import os
import re
import json
import string
import logging
import numpy as np
import email
from email.policy import default
from collections import Counter
import math
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_KB_DIR = os.path.join(_BASE_DIR, '..', 'knowledge_base')
_KB_CACHE = os.path.join(_KB_DIR, 'kaggle_kb.json')

# ──────────────────────────────────────────────
# Stopwords (ID + EN + Custom + Technical MIME/SMTP Noise)
# ──────────────────────────────────────────────
_STOPWORDS = set([
    # English
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "through", "during",
    "before", "after", "above", "below", "between", "out", "off", "over",
    "under", "again", "further", "then", "once", "here", "there", "when",
    "where", "why", "how", "all", "each", "every", "both", "few", "more",
    "most", "other", "some", "such", "no", "nor", "not", "only", "own",
    "same", "so", "than", "too", "very", "just", "because", "but", "and",
    "or", "if", "while", "about", "up", "it", "its", "he", "she", "they",
    "them", "his", "her", "their", "this", "that", "these", "those", "i",
    "me", "my", "we", "us", "our", "you", "your",
    # Indonesian
    "yang", "dan", "di", "ini", "itu", "dengan", "untuk", "dari", "pada",
    "adalah", "ke", "akan", "juga", "atau", "tidak", "sudah", "telah",
    "kami", "kita", "mereka", "anda", "saya", "ada", "bisa", "dalam",
    "oleh", "karena", "seperti", "setelah", "sebelum", "jika", "maka",
    "bahwa", "saat", "bila", "sedang", "secara", "lebih", "sangat", "sini",
    
    # --- NOISE TEKNIS: SERVER, MIME, SMTP, & HTML ---
    "deliveredto", "received", "smtp", "arcseal", "xreceived", "contenttype",
    "contenttransferencoding", "multipartalternative", "charsetbig5", "base64",
    "mime", "boundary", "nextpart", "format", "version", "subject", "date", 
    "cc", "bcc", "xmlns", "http", "https", "www", "com", "org", "net", "href", 
    "src", "charset", "utf8", "textplain", "texthtml", "multipart", "messageid",
    "feedbackid", "contentdisposition", "returnpath", "authenticationresults"
])

# ──────────────────────────────────────────────
# Social Engineering Taxonomy
# ──────────────────────────────────────────────
SE_TAXONOMY = {
    "urgency": {
        "label": "Urgensi / Tekanan Waktu",
        "description": "Memaksa korban bertindak cepat tanpa berpikir kritis.",
        "indicators_id": ["segera", "sekarang juga", "dalam 24 jam", "sebelum terlambat", "batas waktu", "deadline", "mendesak", "darurat", "urgent", "jangan tunda", "waktu terbatas", "hari ini"],
        "indicators_en": ["immediately", "right now", "within 24 hours", "before it's too late", "deadline", "urgent", "asap", "time-sensitive", "act now", "don't delay", "limited time", "expires soon", "last chance", "hurry", "rush", "quickly", "right away", "without delay"]
    },
    "fear": {
        "label": "Ketakutan / Ancaman",
        "description": "Menggunakan ancaman untuk memaksa tindakan.",
        "indicators_id": ["dinonaktifkan", "diblokir", "ditangguhkan", "suspend", "terinfeksi", "virus", "ilegal", "pelanggaran", "denda", "ditutup", "pencurian", "diretas", "kehilangan akses"],
        "indicators_en": ["suspended", "blocked", "disabled", "terminated", "infected", "virus", "illegal", "violation", "penalty", "closed", "stolen", "hacked", "compromised", "locked out", "unauthorized", "breach", "threat", "danger", "warning"]
    },
    "authority": {
        "label": "Otoritas / Impersonasi",
        "description": "Menyamar sebagai figur otoritas atau institusi resmi.",
        "indicators_id": ["dari direksi", "manajemen", "pemerintah", "pajak", "kepolisian", "bank", "admin", "tim keamanan", "departemen IT", "verifikasi resmi", "agency"],
        "indicators_en": ["CEO", "director", "management", "government", "IRS", "police", "bank", "administrator", "security team", "IT department", "official verification", "compliance", "federal", "department", "agency", "representative"]
    },
    "reward": {
        "label": "Hadiah / Iming-Iming",
        "description": "Menawarkan keuntungan untuk memancing tindakan.",
        "indicators_id": ["selamat", "menang", "hadiah", "gratis", "bonus", "cashback", "terpilih", "undian", "voucher", "diskon khusus", "giveaway"],
        "indicators_en": ["congratulations", "winner", "prize", "free", "bonus", "cashback", "selected", "lottery", "voucher", "exclusive offer", "reward", "gift", "giveaway", "jackpot", "lucky"]
    },
    "secrecy": {
        "label": "Kerahasiaan",
        "description": "Meminta korban merahasiakan tindakan dari orang lain.",
        "indicators_id": ["jangan beritahu", "rahasia", "konfidensial", "pribadi", "hanya untuk anda", "jangan diskusikan"],
        "indicators_en": ["don't tell", "secret", "confidential", "private", "for your eyes only", "do not discuss", "keep this between us", "discreet", "classified", "do not share", "strictly private"]
    },
    "credential_request": {
        "label": "Permintaan Kredensial",
        "description": "Meminta data sensitif secara langsung.",
        "indicators_id": ["masukkan password", "verifikasi identitas", "konfirmasi data", "nomor kartu", "kode OTP", "PIN", "data diri", "kata sandi", "nomor rekening", "upload KTP", "scan identitas"],
        "indicators_en": ["enter password", "verify identity", "confirm details", "card number", "OTP code", "PIN", "personal data", "account number", "social security", "login credentials", "update your information", "verify your account", "confirm your identity", "enter your details"]
    },
    "pretexting": {
        "label": "Pretexting / Skenario Palsu",
        "description": "Membuat skenario palsu untuk mendapatkan kepercayaan korban.",
        "indicators_id": ["saya dari bagian", "kami perlu verifikasi", "sesuai kebijakan baru", "pembaruan sistem", "audit keamanan", "pemeliharaan rutin", "perubahan regulasi", "sebagai tindak lanjut"],
        "indicators_en": ["as part of our routine", "due to recent changes", "policy update", "system upgrade", "security audit", "routine maintenance", "regulatory requirement", "as a follow-up", "we need to verify", "scheduled maintenance", "annual review", "mandatory update"]
    },
    "baiting": {
        "label": "Baiting / Umpan",
        "description": "Menawarkan sesuatu yang menarik untuk memancing korban mengklik atau mengunduh.",
        "indicators_id": ["unduh gratis", "download sekarang", "lihat video", "buka lampiran", "klik untuk melihat", "file terlampir", "dokumen penting", "foto pribadi"],
        "indicators_en": ["free download", "download now", "watch video", "open attachment", "click to view", "attached file", "important document", "see attached", "view document", "check this out", "click here to see", "open this file"]
    },
    "scarcity": {
        "label": "Kelangkaan / Keterbatasan",
        "description": "Menciptakan kesan kelangkaan untuk mendorong tindakan cepat.",
        "indicators_id": ["stok terbatas", "hanya tersisa", "penawaran terbatas", "kuota hampir habis", "kesempatan terakhir", "slot terbatas", "hanya hari ini", "edisi terbatas"],
        "indicators_en": ["limited stock", "only remaining", "limited offer", "running out", "last opportunity", "limited slots", "today only", "limited edition", "while supplies last", "few spots left", "almost gone", "selling fast"]
    },
    "social_proof": {
        "label": "Bukti Sosial / Konsensus",
        "description": "Menggunakan perilaku orang lain untuk mempengaruhi korban.",
        "indicators_id": ["ribuan orang telah", "sudah digunakan oleh", "terbukti", "dipercaya oleh", "bergabunglah dengan", "jutaan pengguna", "rekomendasi dari", "testimoni"],
        "indicators_en": ["thousands of people", "already used by", "proven", "trusted by", "join millions", "millions of users", "recommended by", "testimonial", "everyone is doing", "most popular", "best seller", "top rated"]
    },
    "curiosity": {
        "label": "Rasa Ingin Tahu",
        "description": "Membangkitkan rasa ingin tahu untuk memancing klik atau tindakan.",
        "indicators_id": ["anda tidak akan percaya", "rahasia terungkap", "lihat apa yang terjadi", "mengejutkan", "terungkap", "fakta mengejutkan", "tahukah anda", "cari tahu"],
        "indicators_en": ["you won't believe", "secret revealed", "see what happened", "shocking", "exposed", "surprising facts", "did you know", "find out", "discover the truth", "unbelievable", "must see", "you need to see this"]
    },
    "intimidation": {
        "label": "Intimidasi / Ancaman Hukum",
        "description": "Menggunakan ancaman hukum atau tindakan keras untuk memaksa kepatuhan.",
        "indicators_id": ["tindakan hukum", "proses hukum", "penuntutan", "akan dilaporkan", "sanksi", "pelanggaran hukum", "denda administratif", "surat peringatan"],
        "indicators_en": ["legal action", "prosecution", "lawsuit", "will be reported", "sanctions", "law enforcement", "administrative penalty", "warning notice", "court order", "arrest warrant", "criminal charges", "subpoena"]
    },
    "impersonation": {
        "label": "Impersonasi Layanan",
        "description": "Meniru tampilan atau gaya komunikasi layanan/brand terkenal.",
        "indicators_id": ["tim dukungan", "layanan pelanggan", "pusat bantuan", "notifikasi sistem", "pesan otomatis", "dari sistem", "pemberitahuan resmi", "tim verifikasi"],
        "indicators_en": ["support team", "customer service", "help center", "system notification", "automated message", "from system", "official notice", "verification team", "account team", "billing department", "service desk", "no-reply"]
    },
    "emotional_manipulation": {
        "label": "Manipulasi Emosional",
        "description": "Memanfaatkan emosi seperti simpati, rasa bersalah, atau kasihan.",
        "indicators_id": ["tolong bantu", "mohon bantuan", "saya membutuhkan", "korban bencana", "anak yatim", "donasi", "kemanusiaan", "amal", "sedekah"],
        "indicators_en": ["please help", "i need your help", "desperately need", "disaster victim", "orphan", "donation", "charity", "humanitarian", "dying wish", "cancer patient", "stranded", "emergency funds", "life or death"]
    },
    "sextortion": {
        "label": "Sextortion / Pemerasan Digital",
        "description": "Mengancam untuk menyebarkan data pribadi, video, atau foto intim kecuali korban membayar tebusan (biasanya Bitcoin/kripto).",
        "indicators_id": [
            "bitcoin", "transfer bitcoin", "dompet bitcoin", "kripto", "cryptocurrency",
            "saya merekam", "rekaman anda", "video pribadi", "webcam", "kamera",
            "saya memantau", "saya mengawasi", "akses perangkat", "akses email",
            "sebarkan video", "kirim ke kontak", "kirim ke teman", "publik",
            "bayar", "transfer uang", "tebusan", "membayar",
            "kata sandi anda", "password anda", "saya meretas", "diretas",
            "perangkat anda", "riwayat browsing", "aktivitas online",
            "remote access", "program jarak jauh",
        ],
        "indicators_en": [
            "bitcoin", "bitcoin wallet", "btc", "crypto", "cryptocurrency", "usdt",
            "i recorded", "recorded you", "your private", "webcam", "camera",
            "i was monitoring", "i was watching", "access your devices", "access your email",
            "send to your contacts", "send to your friends", "make them public", "share your videos",
            "make a transfer", "pay me", "payment", "ransom",
            "your password", "i hacked", "i managed to access", "gained access",
            "your devices", "browsing history", "online activity",
            "remote access", "installed a program",
        ]
    },
}

LEGITIMATE_SENDERS = {
    "sendgrid.net", "amazonses.com", "mailchimp.com", "mailgun.org",
    "mandrillapp.com", "postmarkapp.com", "sparkpostmail.com",
    "google.com", "gmail.com", "googlemail.com", "microsoft.com",
    "outlook.com", "hotmail.com", "live.com", "apple.com", "icloud.com",
    "yahoo.com", "facebook.com", "facebookmail.com", "instagram.com",
    "meta.com", "twitter.com", "x.com", "linkedin.com", "github.com",
    "gitlab.com", "slack.com", "discord.com", "shopee.co.id", "shopee.co.id",
    "tokopedia.com", "bukalapak.com", "lazada.co.id", "blibli.com",
    "amazon.com", "ebay.com", "bca.co.id", "klikbca.com", "bni.co.id",
    "bri.co.id", "bankmandiri.co.id", "gopay.co.id", "gojek.com",
    "grab.com", "ovo.id", "dana.id", "zoom.us", "dropbox.com", "notion.so",
    "telkomsel.com", "indosat.com", "xl.co.id", "go.id", "pajak.go.id",
    "ajaib.co.id", "bibit.id", "stockbit.com", "bareksa.com", "permatabank.com",
}

PHISHING_KNOWLEDGE_BASE = []
_vectorizer = None
_kb_matrix = None

def _extract_email_body(text: str) -> str:
    """Mengekstrak body pesan, mendukung text/plain dan text/html."""
    if not text: return ""
    
    if re.search(r'(?i)^(Delivered-To:|Received:|MIME-Version:|Content-Type:|From:|To:)', text, re.MULTILINE):
        try:
            msg = email.message_from_string(text, policy=default)
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disp = str(part.get('Content-Disposition', ''))
                    if content_type in ['text/plain', 'text/html'] and 'attachment' not in content_disp:
                        try: 
                            payload = part.get_payload(decode=True)
                            if payload:
                                body += payload.decode('utf-8', errors='ignore') + " "
                        except: pass
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='ignore')
                    else:
                        body = msg.get_payload()
                except:
                    body = msg.get_payload()
            
            if body.strip(): 
                return body.strip()
        except:
            pass
            
    return text

def _clean_text(text: str) -> str:
    """Preprocessing text Murni dengan Perlindungan Tingkat Tinggi."""
    pure_body = _extract_email_body(text)
    if not pure_body: return ""
    pure_body = pure_body.lower()
    
    # 1. Hapus CSS & JS
    pure_body = re.sub(r'<style[^>]*>[\s\S]*?</style>', ' ', pure_body)
    pure_body = re.sub(r'<script[^>]*>[\s\S]*?</script>', ' ', pure_body)
    # 2. Hapus HTML Tags
    pure_body = re.sub(r'<[^>]+>', ' ', pure_body)
    
    # 3. RANJAU ANTI-BASE64: Hapus kata yang panjangnya lebih dari 20 karakter
    pure_body = re.sub(r'\b\w{20,}\b', ' ', pure_body)
    
    # 4. Hapus Punctuation
    pure_body = pure_body.translate(str.maketrans("", "", string.punctuation))
    pure_body = re.sub(r'\s+', ' ', pure_body).strip()
    
    # 5. Stopword & Numeric Removal
    tokens = pure_body.split()
    tokens = [t for t in tokens if t not in _STOPWORDS and len(t) > 1 and not t.isnumeric()]
    return " ".join(tokens)

def _load_kb() -> list:
    if os.path.exists(_KB_CACHE):
        try:
            with open(_KB_CACHE, 'r', encoding='utf-8') as f:
                entries = json.load(f)
            if entries and len(entries) > 0:
                return entries
        except Exception as e:
            logger.warning(f"Failed to load KB: {e}")
    return []

def _ensure_kb():
    global PHISHING_KNOWLEDGE_BASE
    if not PHISHING_KNOWLEDGE_BASE:
        PHISHING_KNOWLEDGE_BASE = _load_kb()

def _init_vectorizer():
    global _vectorizer, _kb_matrix
    if _vectorizer is not None: return
    _ensure_kb()
    if not PHISHING_KNOWLEDGE_BASE: return

    kb_texts = [_clean_text(entry["pattern"]) for entry in PHISHING_KNOWLEDGE_BASE]
    
    # MENDUKUNG UNIGRAM (1) DAN BIGRAM (2) SECARA BERSAMAAN
    _vectorizer = TfidfVectorizer(
        max_features=5000, 
        ngram_range=(1, 2), 
        lowercase=True, 
        token_pattern=r'(?u)\b\w+\b'
    )
    _kb_matrix = _vectorizer.fit_transform(kb_texts)

def search_similar_patterns(email_text: str, top_k: int = 5) -> list:
    """Murni TF-IDF Cosine tanpa injeksi paksa dengan Deterministik Sort."""
    _init_vectorizer()
    if _vectorizer is None or _kb_matrix is None: return []

    cleaned = _clean_text(email_text)
    if not cleaned: return []

    query_vec = _vectorizer.transform([cleaned])
    similarities = cosine_similarity(query_vec, _kb_matrix)[0]

    results = []
    # Mengumpulkan semua hasil yang memiliki similarity di atas treshold
    for idx, sim in enumerate(similarities):
        sim_float = float(sim)
        if sim_float > 0.001:
            entry = PHISHING_KNOWLEDGE_BASE[idx].copy()
            entry["similarity"] = round(sim_float, 6)
            entry["similarity_pct"] = round(sim_float * 100, 2)
            entry["_kb_index"] = int(idx)
            results.append(entry)
            
    # TIE-BREAKER: 1. Urutkan berdasarkan similarity tertinggi, 2. Jika sama, urutkan berdasarkan ID (A-Z)
    results.sort(key=lambda x: (-x["similarity"], x.get("id", "")))
    
    return results[:top_k]

def detect_social_engineering(text: str) -> list:
    clean_body = _extract_email_body(text)
    if not clean_body: return []
    text_lower = clean_body.lower()
    text_lower = re.sub(r'<style[^>]*>[\s\S]*?</style>', ' ', text_lower)
    text_lower = re.sub(r'<script[^>]*>[\s\S]*?</script>', ' ', text_lower)
    text_lower = re.sub(r'<[^>]+>', ' ', text_lower)
    
    detected = []
    for tactic_key, tactic_info in SE_TAXONOMY.items():
        matched_words = set()
        all_indicators = tactic_info["indicators_id"] + tactic_info["indicators_en"]
        for word in all_indicators:
            pattern = r'\b' + re.escape(word.lower()) + r'\b'
            if re.search(pattern, text_lower):
                matched_words.add(word)

        if matched_words:
            detected.append({
                "tactic": tactic_key, "label": tactic_info["label"],
                "description": tactic_info["description"],
                "matched_keywords": list(matched_words), "match_count": len(matched_words),
            })
    detected.sort(key=lambda x: x["match_count"], reverse=True)
    return detected

def compute_tfidf_details(email_text: str) -> dict:
    _init_vectorizer()
    if not email_text or not email_text.strip(): return {"error": "Tidak ada teks untuk dianalisis"}
    if _vectorizer is None or _kb_matrix is None: return {"error": "Knowledge base belum tersedia"}

    cleaned_email = _clean_text(email_text)
    if not cleaned_email: return {"error": "Email tidak mengandung kata yang dapat dianalisis"}

    try:
        feature_names = _vectorizer.get_feature_names_out().tolist()

        se_tactics = detect_social_engineering(email_text)
        se_categories = {t["tactic"]: {"label": t["label"], "keywords": t["matched_keywords"], "count": t["match_count"]} for t in se_tactics}

        query_vec = _vectorizer.transform([cleaned_email])
        similarities = cosine_similarity(query_vec, _kb_matrix)[0]

        all_patterns = []
        for i, entry in enumerate(PHISHING_KNOWLEDGE_BASE):
            sim = float(similarities[i])
            all_patterns.append({
                "id": entry["id"], "category": entry["category"], "pattern": entry["pattern"][:200],
                "tactic": entry.get("tactic", "-"), "description": entry.get("description", "-"),
                "risk": entry.get("risk", "TINGGI"), "similarity": round(sim, 6), "similarity_pct": round(sim * 100, 2),
            })
            
        # TIE-BREAKER: 1. Urutkan berdasarkan similarity tertinggi, 2. Jika sama, urutkan berdasarkan ID (A-Z)
        all_patterns.sort(key=lambda x: (-x["similarity"], x.get("id", "")))
        top_pattern = all_patterns[0] if all_patterns else None

        detailed_steps = {}
        if top_pattern and top_pattern["similarity"] > 0.001:
            top_idx = next((i for i, e in enumerate(PHISHING_KNOWLEDGE_BASE) if e["id"] == top_pattern["id"]), -1)
            if top_idx >= 0:
                detailed_steps = _build_detailed_steps(cleaned_email, top_idx, float(similarities[top_idx]), query_vec.toarray()[0])

        return {
            "cleaned_query": cleaned_email[:500], "detailed_steps": detailed_steps,
            "se_categories": se_categories, "total_vocabulary_size": len(feature_names),
            "all_patterns": all_patterns, "top_pattern": top_pattern,
            "max_similarity_pct": round(float(max(similarities)) * 100, 2),
            "kb_total_patterns": len(PHISHING_KNOWLEDGE_BASE)
        }
    except Exception as e:
        logger.error(f"compute_tfidf_details error: {e}")
        return {"error": str(e)}

def _build_detailed_steps(cleaned_query: str, top_kb_idx: int, sklearn_similarity: float, query_dense: np.ndarray) -> dict:
    if _vectorizer is None: return {}

    feature_names = _vectorizer.get_feature_names_out().tolist()
    idf_values = _vectorizer.idf_
    kb_dense = _kb_matrix[top_kb_idx].toarray()[0]
    kb_entry = PHISHING_KNOWLEDGE_BASE[top_kb_idx]
    kb_cleaned = _clean_text(kb_entry["pattern"])

    # Tokenizer otomatis memecah jadi unigram dan bigram berdasarkan ngram_range
    tokenizer = _vectorizer.build_analyzer()
    query_tokens = tokenizer(cleaned_query)
    kb_tokens = tokenizer(kb_cleaned)
    query_tf_counts = Counter(query_tokens)
    kb_tf_counts = Counter(kb_tokens)
    N_docs = len(PHISHING_KNOWLEDGE_BASE)

    overlap_terms = []
    for fidx in range(len(feature_names)):
        q_val = float(query_dense[fidx])
        k_val = float(kb_dense[fidx])
        
        if q_val > 0 and k_val > 0:
            term = feature_names[fidx]
            raw_tf_q = query_tf_counts.get(term, 0)
            raw_tf_k = kb_tf_counts.get(term, 0)
            idf_val = float(idf_values[fidx])
            
            try: df_val = max(1, round(((1 + N_docs) / math.exp(idf_val - 1)) - 1))
            except: df_val = 1
            
            overlap_terms.append({
                "term": term, "tf_query": raw_tf_q, "tf_kb": raw_tf_k,
                "idf": round(idf_val, 6), "df": df_val,
                "unnorm_tfidf_query": round(raw_tf_q * idf_val, 6), 
                "unnorm_tfidf_kb": round(raw_tf_k * idf_val, 6),
                "norm_tfidf_query": round(q_val, 6), "norm_tfidf_kb": round(k_val, 6),
                "product": round(q_val * k_val, 8)
            })

    overlap_terms.sort(key=lambda x: x["product"], reverse=True)
    
    return {
        "kb_pattern_id": kb_entry.get("id", ""), "kb_pattern_category": kb_entry.get("category", ""),
        "overlap_terms": overlap_terms[:10], "overlap_count": len(overlap_terms),
        "dot_product": round(sum(t["product"] for t in overlap_terms), 8),
        "query_norm": round(float(np.linalg.norm(query_dense)), 6),
        "kb_norm": round(float(np.linalg.norm(kb_dense)), 6),
        "cosine_similarity": round(sklearn_similarity, 6),
        "cosine_pct": round(sklearn_similarity * 100, 2),
        "total_kb_docs": N_docs,
        "query_tokens_sample": cleaned_query.split()[:20],
        "kb_tokens_sample": kb_cleaned.split()[:20],
    }

def build_rag_context(email_text: str, spoof_analysis: dict = None) -> dict:
    similar = search_similar_patterns(email_text, top_k=5)
    se_tactics = detect_social_engineering(email_text)
    is_whitelisted = False
    if spoof_analysis:
        is_whitelisted = is_known_legitimate_sender(spoof_analysis.get("from_domain", ""))

    top_match = similar[0] if similar else None
    highest_sim = top_match["similarity"] if top_match else 0.0
    
    # --- PERBAIKAN FALSE POSITIVE (SINKRONISASI KNOWLEDGE BASE) ---
    # Ekstrak level risiko dan kategori asli dari file kaggle_kb.json
    kb_risk = top_match.get("risk", "TINGGI") if top_match else "RENDAH"
    kb_category = top_match.get("category", "unknown") if top_match else "unknown"

    rag_risk_level = "RENDAH"
    
    # Jika hasil RAG mencocokkan teks dengan kategori 'legitimate' 
    # atau memiliki risk 'AMAN' / 'RENDAH', abaikan skor similarity yang tinggi dan paksa menjadi aman.
    if kb_category == "legitimate" or kb_risk in ["AMAN", "RENDAH"]:
        rag_risk_level = "RENDAH"
    else:
        # Logika normal untuk kategori Phishing
        if highest_sim > 0.25: 
            rag_risk_level = kb_risk # Gunakan tingkat risiko bawaan dari JSON (biasanya TINGGI)
        elif highest_sim > 0.12: 
            # Jika tingkat kemiripan sedang, tetapkan ke SEDANG kecuali JSON menyatakan AMAN
            rag_risk_level = "SEDANG" if kb_risk not in ["AMAN", "RENDAH"] else "RENDAH"

    return {
        "top_match": {
            "id": top_match.get("id", "") if top_match else "",
            "category": kb_category,
            "similarity": highest_sim, "similarity_pct": round(highest_sim * 100, 2),
            "tactic": top_match.get("tactic", "") if top_match else "",
            "description": top_match.get("description", "-") if top_match else "-",
            "risk": kb_risk,
        },
        "similar_patterns": similar, "se_tactics": se_tactics, "is_whitelisted": is_whitelisted,
        "highest_similarity": highest_sim, "highest_match_category": kb_category,
        "rag_risk_level": rag_risk_level,
    }

def is_known_legitimate_sender(domain: str) -> bool:
    if not domain: return False
    domain = domain.lower().strip()
    if domain in LEGITIMATE_SENDERS: return True
    for legit in LEGITIMATE_SENDERS:
        if domain.endswith(f".{legit}"): return True
    return False