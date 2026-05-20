"""
llm_evaluator.py v6.0 — Single Call AI Evaluator (Token Optimized & 100% Synchronized)
=====================================================================================
- Menggunakan SATU kali pemanggilan API untuk menghemat Token (Boros API Fix).
- AI menghasilkan narasi utama sekaligus narasi semantik TF-IDF agar 100% selaras.
- Mempertahankan model "gemini-3.1-flash-lite-preview" sesuai permintaan.
"""

import os
import json
import re
import google.generativeai as genai

def generate_narrative(email_text: str,
                       score_result: dict,
                       spoof_analysis: dict,
                       url_analysis: list,
                       domain_info: dict,
                       rag_context: dict = None,
                       content_analysis: dict = None,
                       attachment_analysis: dict = None) -> dict:

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return _fallback_narrative("API Key Gemini tidak ditemukan.")

    try:
        genai.configure(api_key=api_key)
        # Sesuai permintaan: Dibiarkan gemini-3.1-flash-lite-preview
        model = genai.GenerativeModel(
            "gemini-3.1-flash-lite-preview",
            generation_config={"response_mime_type": "application/json"}
        )

        active_flags = [
            f"{f['category']} | {f['label']} (+{f['weight']})"
            for f in score_result.get("all_flags", [])
        ]

        breakdown = score_result.get("breakdown", {})
        breakdown_summary = {
            k: f"{v['score']}/{v['max']}" for k, v in breakdown.items()
        }

        primary_domain = domain_info.get("primary", domain_info)

        # Snippet email_text dimasukkan agar AI bisa melakukan penalaran semantik (TF-IDF)
        context = {
            "cuplikan_isi_email_asli": email_text[:1200], 
            "skor_total": score_result["total_score"],
            "status_final": score_result["status"],
            "breakdown_skor": breakdown_summary,
            "flag_aktif": active_flags,
            "domain_pengirim": spoof_analysis.get("from_domain", "-"),
            "domain_return_path": spoof_analysis.get("return_domain", "-"),
            "reply_to_mismatch": spoof_analysis.get("reply_to_mismatch", False),
            "suspicious_hops": len(spoof_analysis.get("suspicious_hops", [])),
            "domain_reputasi": {
                "umur_hari": primary_domain.get("domain_age", "-"),
                "virustotal": primary_domain.get("virustotal_positives", 0),
                "abuseipdb_score": primary_domain.get("abuseipdb_score", 0),
            },
            "url_berisiko": [
                {"url": u.get("url", "")[:50], "risiko": u.get("risk_level", "-")}
                for u in url_analysis if u.get("risk_level") in ("TINGGI", "SEDANG")
            ][:3]
        }

        rag_section = ""
        if rag_context:
            similar = rag_context.get("similar_patterns", [])
            se_tactics = rag_context.get("se_tactics", [])
            rag_risk = rag_context.get("rag_risk_level", "RENDAH")

            if similar:
                rag_section += f"\nPOLA PHISHING SERUPA DARI DATABASE (RAG - Risiko: {rag_risk}):\n"
                for i, p in enumerate(similar[:2], 1):
                    rag_section += f"{i}. [{p.get('category', '-')}] Kemiripan: {p.get('similarity', 0):.0%} — Teks Database: {p.get('pattern', '-')[:150]}\n"

            if se_tactics:
                rag_section += "\nTAKTIK SOCIAL ENGINEERING TERDETEKSI:\n"
                for t in se_tactics[:3]:
                    rag_section += f"- {t.get('label', '-')} (kata: {', '.join(t.get('matched_keywords', [])[:3])})\n"

        content_section = f"Risiko Konten: {content_analysis.get('risk_summary', '-') if content_analysis else '-'}"

        prompt = f"""
        Anda adalah Analis Keamanan Siber senior.
        Sistem skoring deterministik telah mengevaluasi email ini dengan status "{score_result['status']}" dan skor {score_result['total_score']}/100.
        SISTEM SCORING MENGGUNAKAN 4 KATEGORI:
        - S_A: Autentikasi Email & Header (SPF, DKIM, DMARC, domain mismatch, Reply-To, Received hops)
        - S_B: Analisis URL & File (encoding, punycode, ekstensi, attachment, subdomain palsu)
        - S_C: Konten & Social Engineering (pola manipulasi, permintaan kredensial, RAG similarity)
        - S_D: Reputasi Domain & Redirect (OSINT, VirusTotal, AbuseIPDB, redirect chain)

        KONTEKS FORENSIK:
        {json.dumps(context, ensure_ascii=False, indent=2)}
        {rag_section}
        {content_section}

        TUGAS ANDA:
        Berdasarkan SEMUA data di atas (scoring + RAG + konten + attachment + url + domain + redirect), hasilkan narasi penjelasan.
        Hasilkan output berformat JSON yang MENDUKUNG DAN SELARAS dengan status "{score_result['status']}". 
        DILARANG KERAS memberikan analisis yang bertentangan dengan status tersebut.

        Format JSON yang WAJIB dihasilkan:
        {{
          "saran": " ATURAN SARAN BERDASARKAN STATUS:
- Jika status = "AMAN" (skor ≤ 25):
  * WAJIB dimulai dengan: "Email ini teridentifikasi AMAN..." atau "Email ini sah..."
  * DILARANG KERAS menyarankan "hapus email" atau "jangan buka" atau kata negatif lain.
  * Jelaskan mengapa email ini aman (autentikasi lengkap, domain terpercaya, dsb).
  * Jika ada sedikit temuan minor di S_C (kata kunci SE yg kebetulan cocok), jelaskan bahwa
    ini adalah konteks wajar (misal: email resmi bank memang menyebut "PIN/OTP" sebagai edukasi,
    bukan sebagai teknik phishing). Kata kunci SE bisa muncul di email sah.
  * Boleh tutup dengan saran umum berhati-hati sebagai standar keamanan.

- Jika status = "MENCURIGAKAN" (skor 30–65):
  * WAJIB dimulai dengan: "Email ini terdeteksi MENCURIGAKAN..." atau "Waspadai email ini..."
  * Jelaskan indikator yang memicunya dan sarankan verifikasi lebih lanjut.
  * Jangan langsung menyuruh hapus — sarankan konfirmasi melalui saluran resmi.

- Jika status = "BERBAHAYA" (skor ≥ 66):
  * WAJIB dimulai dengan: "Segera hapus email ini..." atau "Email ini BERBAHAYA..."
  * Berikan peringatan keras dan sarankan tindakan pencegahan spesifik.
  * Sebutkan risiko (pencurian data, malware, social engineering)."

          "rincian": [        
ATURAN RINCIAN:
"rincian: Array 4 string. Masing-masing TEPAT satu kalimat analitis sesuai kategori scoring:",
"rincian[0]: [S_A] Temuan autentikasi (SPF/DKIM/DMARC/mismatch/Reply-To/Received chain/Received Hops/Autentikasi (Raw)/Kesamaan Domain)",
"rincian[1]: [S_B] Temuan URL & file (encoding, punycode, ekstensi, brand, attachment)",
"rincian[2]: [S_C] Temuan konten & social engineering (pola manipulasi, RAG similarity)",
"rincian[3]: [S_D] Temuan reputasi domain + redirect (VirusTotal, AbuseIPDB, Urlscan.io, shodan.io, redirect chain)."
          ],
          "analisis_semantik_rag": "Dua paragraf penjelasan ringkas mendalam (Gunakan Markdown) khusus untuk halaman Analisis TF-IDF. Misi Anda adalah membedah makna email asli vs pola database RAG. JIKA status email AMAN namun RAG menemukan kemiripan, ANDA WAJIB membela email tersebut dengan menjelaskan bahwa TF-IDF mengalami 'False Positive' karena kecocokan kata-kata umum yang buta konteks dan berikan jawaban seharusnya yang benar kategorinya jika diluar konteks email yang dimasukan karena TF_IDF kurang akurat. JIKA status BERBAHAYA, jelaskan letak persamaan taktik penipuannya jika email asli dan pola phishing KB sesuai konteks."
        }}
        """
        
        response = model.generate_content(prompt)
        text = response.text.strip()

        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            text = match.group(0)

        parsed = json.loads(text)
        return {
            "saran": parsed.get("saran", "Tidak ada saran."),
            "rincian": parsed.get("rincian", []),
            "analisis_semantik_rag": parsed.get("analisis_semantik_rag", "Analisis semantik tidak tersedia.")
        }

    except json.JSONDecodeError as e:
        return _fallback_narrative(f"Format respons AI tidak valid (Bukan JSON). Detail: {str(e)}")
    except Exception as e:
        return _fallback_narrative(f"Gagal menghubungi layanan API Gemini. Detail Error: {str(e)}")


def _fallback_narrative(pesan_error: str) -> dict:
    return {
        "saran": pesan_error,
        "rincian": [
            "[S_A] Sistem AI sedang offline. Periksa kolom SPF/DKIM/DMARC.",
            "[S_B] Periksa kolom risiko URL Analyzer.",
            "[S_C] Periksa panel Konten & Social Engineering.",
            "[S_D] Periksa panel Reputasi Domain."
        ],
        "analisis_semantik_rag": f"**Gagal memuat analisis Semantik AI:** {pesan_error}"
    }