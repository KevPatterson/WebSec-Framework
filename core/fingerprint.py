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
        except Exception as e:
            self.logger.error(f"Error en fingerprinting: {e}")

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
