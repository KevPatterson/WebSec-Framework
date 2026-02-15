"""
Módulo de fingerprinting tecnológico: servidor, frameworks, headers, cookies, WAF.
"""


import requests
from core.logger import get_logger
from urllib.parse import urlparse

class Fingerprinter:
    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.logger = get_logger("fingerprint")
        self.results = {}
        # Crear carpeta de reporte con timestamp
        from datetime import datetime
        self.scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = f"reports/scan_{self.scan_timestamp}"

    def run(self):
        """Realiza fingerprinting sobre el objetivo."""
        self.logger.info(f"Iniciando fingerprinting en: {self.target_url}")
        try:
            resp = requests.get(self.target_url, timeout=10, allow_redirects=True)
            self.results["status_code"] = resp.status_code
            self.results["headers"] = dict(resp.headers)
            self.results["cookies"] = resp.cookies.get_dict()
            self.results["server"] = resp.headers.get("Server", "Desconocido")
            self.results["powered_by"] = resp.headers.get("X-Powered-By", "Desconocido")
            self.results["waf"] = self._detect_waf(resp)
            self.logger.info(f"Servidor: {self.results['server']}, X-Powered-By: {self.results['powered_by']}")
            if self.results["waf"]:
                self.logger.warning(f"Posible WAF detectado: {self.results['waf']}")
            
            # Exportar resultados de fingerprinting
            self._export_results()
        except Exception as e:
            self.logger.error(f"Error en fingerprinting: {e}")
    
    def _export_results(self):
        """Exporta los resultados del fingerprinting a JSON."""
        import os, json
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            fingerprint_path = os.path.join(self.report_dir, "fingerprint.json")
            with open(fingerprint_path, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Resultados de fingerprinting exportados en {fingerprint_path}")
        except Exception as e:
            self.logger.error(f"Error al exportar resultados de fingerprinting: {e}")

    def _detect_waf(self, resp):
        # Detección básica de WAF por headers comunes
        waf_headers = [
            ("X-Akamai-Transformed", "Akamai"),
            ("X-Sucuri-ID", "Sucuri"),
            ("X-CDN", "CDN/WAF"),
            ("X-Distil-CS", "Distil Networks"),
            ("X-Cloudflare", "Cloudflare"),
            ("CF-RAY", "Cloudflare"),
            ("Server", "cloudflare"),
            ("X-WAF", "Genérico"),
        ]
        for header, name in waf_headers:
            if header in resp.headers and name.lower() in resp.headers[header].lower():
                return name
        # Heurística: cookies sospechosas
        for cookie in resp.cookies:
            if "waf" in cookie.name.lower() or "cfduid" in cookie.name.lower():
                return "WAF/Cookie"
        return None
