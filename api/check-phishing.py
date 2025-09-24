from http.server import BaseHTTPRequestHandler
import json
import re

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))
        text = data.get('text', '')

        is_phishing = self.analyze_text(text)

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response_data = {'is_phishing': is_phishing}
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

    def analyze_text(self, text):
        # Normalisasi teks menjadi huruf kecil untuk analisis yang konsisten
        normalized_text = text.lower()
        
        # Aturan Deteksi Phishing Berdasarkan Pengetahuan Anda
        
        # 1. Kata Kunci yang Mendesak atau Mengancam
        keywords_phishing = ['segera', 'penting', 'verifikasi akun', 'tindakan diperlukan', 'kata sandi kadaluarsa', 'ditangguhkan', 'dihentikan']
        for keyword in keywords_phishing:
            if keyword in normalized_text:
                return True
                
        # 2. Tautan (URL) yang Mencurigakan
        # Menggunakan regex untuk menemukan URL
        urls = re.findall(r'https?://\S+', normalized_text)
        for url in urls:
            # Contoh sederhana: Periksa jika ada IP address di URL
            if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                return True
            
            # Contoh lain: Cek Punycode (nama domain yang disamarkan)
            if 'xn--' in url:
                return True
                
            # Contoh lain: Domain yang tidak valid atau sub-domain yang aneh
            if 'login-' in url and '.com' not in url:
                return True
                
            # Contoh lain: Domain yang menggunakan banyak sub-domain
            if url.count('.') > 3:
                return True
                
        # 3. Permintaan Informasi Pribadi
        if 'masukkan sandi' in normalized_text or 'nomor kartu kredit' in normalized_text:
            return True
            
        # Jika tidak ada satupun aturan di atas yang cocok
        return False