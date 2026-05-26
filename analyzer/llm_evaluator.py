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
            "gemini-2.5-flash",
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

        # Snippet email_text dimasukkan agar AI bisa melakukan penalaran
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
        Sistem skoring deterministik (berbasis teknis) telah mengevaluasi email ini dengan status "{score_result['status']}" dan skor {score_result['total_score']}/100.
        SISTEM SCORING MENGGUNAKAN 4 KATEGORI:
        - S_A: Autentikasi Email & Header
        - S_B: Analisis URL & File
        - S_C: Konten & Social Engineering
        - S_D: Reputasi Domain & Redirect

        KONTEKS FORENSIK:
        {json.dumps(context, ensure_ascii=False, indent=2)}
        {rag_section}
        {content_section}

        TUGAS ANDA:
        Berdasarkan SEMUA data di atas, hasilkan output berformat JSON. 
        Meskipun Anda mengacu pada status deterministik "{score_result['status']}", Anda memiliki wewenang analitis untuk menambahkan PERINGATAN jika mendeteksi anomali yang lolos dari skoring teknis (misalnya rekayasa sosial atau teks salinan/copy-paste).

        Format JSON yang WAJIB dihasilkan:
        {{
          "saran": " ATURAN SARAN BERDASARKAN STATUS:
- Jika status = "AMAN" (skor ≤ 25):
  * Mulai dengan menjelaskan mengapa sistem teknis menganggapnya aman (misal: tidak ada link bahaya, domain terautentikasi).
  * NAMUN, lakukan pengecekan silang! Jika isi teks meminta data sensitif, uang, atau menggunakan bahasa mendesak, WAJIB tambahkan paragraf baru berawalan: '⚠️ CATATAN KEHATI-HATIAN: Meskipun secara teknis email ini bersih, gaya bahasanya menyerupai rekayasa sosial. Jangan berikan kredensial atau klik tautan apa pun.'

- Jika status = "MENCURIGAKAN" (skor 30–65):
  * Mulai dengan: 'Waspadai email ini...'
  * Jelaskan indikator anehnya secara sederhana dan sarankan konfirmasi ke instansi resmi melalui jalur luar (jangan balas email).

- Jika status = "BERBAHAYA" (skor ≥ 66):
  * Mulai dengan: 'Email ini BERBAHAYA...'
  * Berikan peringatan keras dan sarankan penghapusan atau pemblokiran. Sebutkan risiko pastinya."

          "rincian": [        
"rincian[0]: [S_A] Temuan autentikasi (SPF/DKIM/DMARC/mismatch/Reply-To/Received chain)",
"rincian[1]: [S_B] Temuan URL & file (encoding, punycode, ekstensi, brand, attachment)",
"rincian[2]: [S_C] Temuan konten & social engineering (pola manipulasi, RAG similarity)",
"rincian[3]: [S_D] Temuan reputasi domain + redirect (VirusTotal, AbuseIPDB, Urlscan, Shodan, redirect chain)."
          ],
          
          "analisis_semantik_rag": "Dua paragraf penjelasan ringkas mendalam (Gunakan Markdown). 
ATURAN ANALISIS RAG: 
1. EVALUASI HASIL RAG: Anda WAJIB membandingkan kategori dari RAG Database (kaggle_kb.json) dengan makna sebenarnya dari 'cuplikan_isi_email_asli'.Lakukan CROSS-REFERENCE (Cek Silang). Bandingkan nama entitas di dalam teks email asli dengan nama 'domain_pengirim'. 
2. KOREKSI FALSE POSITIVE (Email Legit dituduh Phishing): Jika status email 'AMAN' namun RAG menuduhnya sebagai 'spear_phishing' atau ancaman lain (seperti kasus notifikasi reset password GitHub yang sah), Anda WAJIB menyatakan bahwa ini adalah 'False Positive pada algoritma TF-IDF'. Jelaskan bahwa RAG tertipu oleh kesamaan kosa kata teknis (misal: 'password', 'reset') yang lumrah digunakan dalam notifikasi sistem yang sah. Jika teks email berpura-pura menjadi institusi besar (misal: Bank, Kampus, Perusahaan) TETAPI dikirim menggunakan domain publik (seperti @gmail.com) atau domain acak, MAKA JELASKAN bahwa penipu bisa saja menyalin (copy-paste) teks resmi untuk mengelabui korban.
3. VALIDASI TRUE POSITIVE: Jika status 'BERBAHAYA' dan kategori RAG memang cocok dengan isi teks scam, jelaskan taktik manipulasi psikologis apa yang sedang digunakan pelaku berdasarkan pola di database. Jangan pernah membela email scam. Jika RAG menemukan kemiripan tinggi dengan database phishing, jelaskan taktik apa yang sedang dicoba oleh pelaku berdasarkan pola kemiripan tersebut. Jika Sama-sama Aman jelaskan bahwa teks tersebut memang bahasa korespondensi wajar tanpa manipulasi"
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