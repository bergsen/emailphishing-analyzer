import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

MAX_REDIRECT_CHAIN = 15

# ──────────────────────────────────────────────────────────────────────
# 💡 FUNGSI PENJELASAN UNTUK PENGGUNA AWAM (NON-TEKNIS)
# ──────────────────────────────────────────────────────────────────────
def get_status_description(status, url):
    """Memberikan penjelasan bahasa Indonesia yang mudah dipahami."""
    u_lower = url.lower()
    status_str = str(status)

    # 1. Deteksi Infrastruktur Email (Bukan Website Publik)
    infrastruktur_keywords = ['mx.', 'mail.', 'messaging.', 'mailgun', 'sendgrid', 'smtp']
    if any(k in u_lower for k in infrastruktur_keywords):
        if status_str in ["Error/Unreachable", "SSL Error", "404", "403", "Timeout"]:
            return "Normal. Ini adalah server pengirim email otomatis, bukan website untuk dibuka di browser."

    # 2. Penjelasan berdasarkan Status Code
    descriptions = {
        "200": "Aman. Halaman tujuan berhasil dimuat dengan sempurna.",
        "301": "Pengalihan Permanen. Biasanya digunakan untuk pindah ke alamat web yang lebih baru/aman.",
        "302": "Pengalihan Sementara. Mengarahkan Anda secara otomatis ke halaman lain (misal: ke HTTPS).",
        "404": "Tidak Ditemukan. Halaman yang dicari tidak ada di server tersebut.",
        "403": "Akses Ditolak. Server ada, tapi Anda tidak diizinkan membukanya secara publik.",
        "SSL Error": "Masalah Sertifikat. Sering terjadi pada server internal perusahaan yang dikunci untuk umum.",
        "Error/Unreachable": "Tidak Terjangkau. Server tidak merespons koneksi web (mungkin server mati atau hanya untuk internal).",
        "Timeout": "Waktu Habis. Server terlalu lama merespons, kemungkinan karena trafik tinggi atau proteksi.",
        "Invalid Schema": "Format Tidak Valid. Alamat yang dimasukkan bukan merupakan alamat web standar.",
        "Missing Schema": "Format Tidak Lengkap. Alamat yang dimasukkan kekurangan protokol standar (http://).",
        "Non-HTTP URI": "Tautan Internal. Ini bukan tautan web, melainkan kode internal (seperti data gambar atau skrip)."
    }

    return descriptions.get(status_str, f"Status Terdeteksi: {status_str}. Tidak ada anomali berbahaya yang ditemukan secara langsung.")

# ──────────────────────────────────────────────────────────────────────


def _get_netloc(url: str) -> str:
    try:
        return urlparse(url).netloc
    except Exception:
        return ""


def _is_same_base_domain(d1: str, d2: str) -> bool:
    """Check if two domains are the same ignoring www prefix."""
    def strip_www(d):
        return d[4:] if d.startswith("www.") else d
    return strip_www(d1.lower()) == strip_www(d2.lower())


def trace_redirect(url: str) -> list:
    """
    Lacak seluruh rantai redirect dari URL awal.
    Coba dengan SSL verification terlebih dahulu, fallback tanpa verify.
    """
    chain = []
    
    # ── 1. SANITASI INPUT MANUAL ──
    url = url.strip()

    # Cegah crash jika URL adalah data URI, Javascript, atau Mailto
    if url.lower().startswith(('data:', 'javascript:', 'mailto:')):
        return [{
            "url": url[:100] + ("..." if len(url) > 100 else ""),
            "status": "Non-HTTP URI",
            "explanation": get_status_description("Non-HTTP URI", url),
            "cross_domain": False,
            "ssl_verified": False,
        }]

    # Tambahkan scheme http:// jika bare domain (input manual)
    if not url.lower().startswith('http://') and not url.lower().startswith('https://'):
        url = 'http://' + url
    # ───────────────────────────────

    for verify_ssl in (True, False):
        try:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=8,
                headers=_HEADERS,
                verify=verify_ssl,
                stream=True,
            )

            all_responses = list(response.history) + [response]
            prev_domain = None

            for r in all_responses[:MAX_REDIRECT_CHAIN]:
                current_domain = _get_netloc(r.url)
                cross = bool(
                    prev_domain and current_domain
                    and prev_domain != current_domain
                    and not _is_same_base_domain(prev_domain, current_domain)
                )
                chain.append({
                    "url": r.url,
                    "status": r.status_code,
                    "explanation": get_status_description(r.status_code, r.url),
                    "cross_domain": cross,
                    "ssl_verified": verify_ssl,
                })
                prev_domain = current_domain

            if len(all_responses) > MAX_REDIRECT_CHAIN:
                chain.append({
                    "url": "... (chain terlalu panjang, dipotong)",
                    "status": "Truncated",
                    "explanation": "Tautan ini mengalihkan terlalu banyak, berpotensi looping atau disembunyikan.",
                    "cross_domain": False,
                    "ssl_verified": verify_ssl,
                })

            response.close()
            return chain

        except requests.exceptions.SSLError:
            if verify_ssl:
                continue  # Coba lagi dengan verify=False
            chain.append({
                "url": url, "status": "SSL Error",
                "explanation": get_status_description("SSL Error", url),
                "cross_domain": False, "ssl_verified": False,
            })
        except requests.exceptions.ConnectionError:
            chain.append({
                "url": url, "status": "Error/Unreachable",
                "explanation": get_status_description("Error/Unreachable", url),
                "cross_domain": False, "ssl_verified": verify_ssl,
            })
        except requests.exceptions.Timeout:
            chain.append({
                "url": url, "status": "Timeout",
                "explanation": get_status_description("Timeout", url),
                "cross_domain": False, "ssl_verified": verify_ssl,
            })
        except requests.exceptions.InvalidSchema:
            chain.append({
                "url": url, "status": "Invalid Schema",
                "explanation": get_status_description("Invalid Schema", url),
                "cross_domain": False, "ssl_verified": verify_ssl,
            })
        except requests.exceptions.MissingSchema:
            chain.append({
                "url": url, "status": "Missing Schema",
                "explanation": get_status_description("Missing Schema", url),
                "cross_domain": False, "ssl_verified": verify_ssl,
            })
        except requests.exceptions.RequestException as e:
            err_name = f"Error: {type(e).__name__}"
            chain.append({
                "url": url,
                "status": err_name,
                "explanation": get_status_description(err_name, url),
                "cross_domain": False, "ssl_verified": verify_ssl,
            })
        
        # Keluar dari loop try-catch (True, False) jika sudah dapat error non-SSL
        break

    return chain


def trace_all_redirects(urls: list, max_urls: int = 5) -> list:
    """
    Trace redirect untuk SEMUA URL (hingga max_urls).
    Returns list of dicts dengan url_source dan chain.
    """
    if not urls:
        return []

    urls_to_trace = urls[:max_urls]
    all_results = []

    with ThreadPoolExecutor(max_workers=min(len(urls_to_trace), 3)) as ex:
        futures = {ex.submit(trace_redirect, url): url for url in urls_to_trace}
        for fut in as_completed(futures):
            source_url = futures[fut]
            try:
                chain = fut.result()
            except Exception:
                chain = [{
                    "url": source_url,
                    "status": "Error Internal",
                    "explanation": "Terjadi kesalahan internal pada pelacak sistem.",
                    "cross_domain": False,
                    "ssl_verified": False,
                }]
            all_results.append({
                "source_url": source_url,
                "chain": chain,
                "has_cross_domain": any(h.get("cross_domain") for h in chain),
                "has_error": any(
                    isinstance(h.get("status"), str) for h in chain
                ),
            })

    return all_results