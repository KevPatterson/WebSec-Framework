"""
Módulo de crawling inteligente para descubrimiento de URLs y parámetros.
Extensible para soporte JS dinámico (Playwright).
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.logger import get_logger

class Crawler:
    def _extract_js_endpoints(self, js_code, base_url):
        """Extrae endpoints AJAX, rutas y parámetros de código JS."""
        import re
        endpoints = set()
        # Buscar rutas tipo '/api/...' o '/ajax/...'
        for match in re.findall(r'(["\'])(\/[^"\']{3,})\1', js_code):
            url = urljoin(base_url, match[1])
            endpoints.add(self._normalize_url(url))
        # Buscar URLs absolutas
        for match in re.findall(r'https?://[\w\.-]+(/[\w\./\-\?&%]*)', js_code):
            endpoints.add(self._normalize_url(match[0]))
        # Buscar parámetros AJAX (fetch, XMLHttpRequest, $.ajax)
        for ajax in re.findall(r'(fetch|XMLHttpRequest|\.ajax)\s*\(.*?(["\'])([^"\']+)(["\'])', js_code):
            url = urljoin(base_url, ajax[2])
            endpoints.add(self._normalize_url(url))
        return endpoints

    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.visited = set()
        self.found_urls = set()
        self.forms = []
        self.logger = get_logger("crawler")
        self.exported = False
        self.js_endpoints = set()
        self.use_js_crawling = bool(config.get("js_crawling", False))
        self.js_browser = config.get("js_browser", "auto").lower()  # auto|chrome|firefox|edge|chromium
        self.crawl_tree = {}  # Estructura árbol: {url: [hijos]}
        # Crear carpeta de reporte con timestamp
        from datetime import datetime
        self.scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = f"reports/scan_{self.scan_timestamp}"

    def run(self):
        """Ejecuta el crawling sobre el objetivo, exprimiendo recursos avanzados."""
        import concurrent.futures
        self.logger.info(f"Iniciando crawling en: {self.target_url}")
        seeds = set([self.target_url])
        # Añadir robots.txt, sitemap.xml, manifest.json y service worker
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = urljoin(base, "/robots.txt")
        sitemap_url = urljoin(base, "/sitemap.xml")
        manifest_url = urljoin(base, "/manifest.json")
        sw_url = urljoin(base, "/service-worker.js")
        seeds.update([robots_url, sitemap_url, manifest_url, sw_url])
        # Crawling concurrente
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(self._crawl, url, 0, 2, None): url for url in seeds}
            concurrent.futures.wait(futures)
        self.logger.info(f"Crawling finalizado. URLs encontradas: {len(self.found_urls)}. Formularios: {len(self.forms)}")
        self.export_results()
        self.export_tree_visual()

    def _normalize_url(self, url):
        # Normaliza la URL: sin fragmentos, parámetros ordenados
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query = "&".join(sorted(parsed.query.split("&"))) if parsed.query else ""
        return f"{base}?{query}" if query else base

    def _is_paginated(self, url):
        # Detecta si la URL es de paginación
        return any(x in url.lower() for x in ["page=", "/page/", "/next", "?p="])

    def _crawl(self, url, depth=0, max_depth=2, parent=None):
        if depth > max_depth:
            return
        norm_url = self._normalize_url(url)
        if norm_url in self.visited:
            return
        self.visited.add(norm_url)
        # Registrar relación padre-hijo
        if parent:
            hijos = self.crawl_tree.setdefault(parent, [])
            if norm_url not in hijos:
                hijos.append(norm_url)
        else:
            self.crawl_tree.setdefault(norm_url, [])
        # Soporte opcional para crawling JS dinámico
        soup = None
        resp = None
        if self.use_js_crawling:
            try:
                from playwright.sync_api import sync_playwright
                import shutil, sys
                browser_type = self.js_browser
                browser_launch = None
                browser_name = None
                with sync_playwright() as p:
                    # Detección automática de navegador
                    if browser_type == "auto":
                        # Prioridad: chrome > edge > firefox > chromium
                        if shutil.which("chrome") or shutil.which("google-chrome"):
                            browser_type = "chrome"
                        elif shutil.which("msedge") or shutil.which("edge"):
                            browser_type = "edge"
                        elif shutil.which("firefox"):
                            browser_type = "firefox"
                        else:
                            browser_type = "chromium"
                    if browser_type == "chrome":
                        browser_launch = p.chromium.launch_persistent_context(user_data_dir="/tmp/chrome-profile", headless=True, channel="chrome")
                        browser_name = "chrome"
                    elif browser_type == "edge":
                        browser_launch = p.chromium.launch_persistent_context(user_data_dir="/tmp/edge-profile", headless=True, channel="msedge")
                        browser_name = "edge"
                    elif browser_type == "firefox":
                        browser_launch = p.firefox.launch(headless=True)
                        browser_name = "firefox"
                    else:
                        browser_launch = p.chromium.launch(headless=True)
                        browser_name = "chromium"
                    # Abrir página
                    if hasattr(browser_launch, "new_page"):
                        page = browser_launch.new_page()
                    else:
                        page = browser_launch.pages[0]
                    page.goto(url, timeout=20000)
                    html = page.content()
                    resp = type('Resp', (), {'text': html, 'status_code': 200})()
                    browser_launch.close()
                    self.logger.info(f"[JS] Crawling dinámico ejecutado en {url} usando navegador: {browser_name}")
            except ImportError:
                self.logger.warning("Playwright no está instalado. Crawling JS dinámico deshabilitado para este escaneo.")
            except Exception as e:
                self.logger.warning(f"Fallo en crawling JS dinámico en {url}: {e}")
        if resp is None:
            resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 WebSecCrawler"})
        if resp.status_code != 200:
            self.logger.warning(f"No se pudo acceder a {url} (status {resp.status_code})")
            return

        self.found_urls.add(norm_url)
        # Usar parser XML para sitemap.xml
        if url.endswith("sitemap.xml"):
            soup = BeautifulSoup(resp.text, "xml")
        else:
            soup = BeautifulSoup(resp.text, "html.parser")

        # Extraer formularios
        self.forms.extend(self.extract_forms(soup, url))
        links = set()
        # Enlaces internos y parámetros
        for link in soup.find_all("a", href=True):
            href = link["href"]
            joined = urljoin(url, href)
            if self._is_internal(joined):
                links.add(self._normalize_url(joined))
                parsed = urlparse(joined)
                if parsed.query:
                    self.logger.info(f"Parámetros encontrados en {joined}: {parsed.query}")
        # Endpoints en scripts JS externos
        for script in soup.find_all("script", src=True):
            js_url = urljoin(url, script["src"])
            if self._is_internal(js_url):
                links.add(self._normalize_url(js_url))
                # Analizar JS externo
                try:
                    js_resp = requests.get(js_url, timeout=8, headers={"User-Agent": "Mozilla/5.0 WebSecCrawler"})
                    if js_resp.status_code == 200 and js_resp.text:
                        js_endpoints = self._extract_js_endpoints(js_resp.text, url)
                        for ep in js_endpoints:
                            links.add(ep)
                            self.js_endpoints.add(ep)
                            self.logger.info(f"[JS externo] Endpoint descubierto: {ep}")
                except Exception as e:
                    self.logger.warning(f"Error analizando JS externo {js_url}: {e}")
        # Endpoints en manifest.json y service worker
        if url.endswith("manifest.json"):
            import json
            try:
                manifest = json.loads(resp.text)
                for k in ["start_url", "scope", "background", "shortcuts", "icons"]:
                    v = manifest.get(k)
                    if isinstance(v, str) and v.startswith("/"):
                        murl = urljoin(url, v)
                        if self._is_internal(murl):
                            links.add(self._normalize_url(murl))
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict):
                                for val in item.values():
                                    if isinstance(val, str) and val.startswith("/"):
                                        murl = urljoin(url, val)
                                        if self._is_internal(murl):
                                            links.add(self._normalize_url(murl))
            except Exception:
                pass
        if url.endswith("service-worker.js"):
            import re
            for match in re.findall(r'"(\/[^"\s]+)"', resp.text):
                sw_url = urljoin(url, match)
                if self._is_internal(sw_url):
                    links.add(self._normalize_url(sw_url))
        # Endpoints de robots.txt y sitemap.xml
        if url.endswith("robots.txt"):
            for line in resp.text.splitlines():
                if line.lower().startswith("allow") or line.lower().startswith("disallow"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and path.startswith("/"):
                            rob_url = urljoin(url, path)
                            if self._is_internal(rob_url):
                                links.add(self._normalize_url(rob_url))
        if url.endswith("sitemap.xml"):
            try:
                for loc in soup.find_all("loc"):
                    sm_url = loc.text.strip()
                    if self._is_internal(sm_url):
                        links.add(self._normalize_url(sm_url))
            except Exception:
                pass
        # Endpoints en comentarios HTML
        for comment in soup.find_all(string=lambda text: isinstance(text, type(soup.comment))):
            if "http" in comment:
                for word in comment.split():
                    if word.startswith("http") and self._is_internal(word):
                        links.add(self._normalize_url(word))
        # Endpoints en atributos data-* y onclick
        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                if attr.startswith("data-") or attr in ("onclick", "onmouseover", "onload"):
                    if isinstance(val, str) and (val.startswith("/") or val.startswith("http")):
                        durl = urljoin(url, val)
                        if self._is_internal(durl):
                            links.add(self._normalize_url(durl))
        # Endpoints en comentarios HTML
        for comment in soup.find_all(string=lambda text: isinstance(text, type(soup.comment))):
            if "http" in comment:
                for word in comment.split():
                    if word.startswith("http") and self._is_internal(word):
                        links.add(self._normalize_url(word))
        # Endpoints de JS embebido
        for script in soup.find_all("script"):
            if script.string:
                import re
                for match in re.findall(r'"(\/[^"\s]+)"', script.string):
                    js_url = urljoin(url, match)
                    if self._is_internal(js_url):
                        links.add(self._normalize_url(js_url))
                # Analizar JS embebido
                js_endpoints = self._extract_js_endpoints(script.string, url)
                for ep in js_endpoints:
                    links.add(ep)
                    self.js_endpoints.add(ep)
                    self.logger.info(f"[JS embebido] Endpoint descubierto: {ep}")
        # Paginación automática
        paginated = set(l for l in links if self._is_paginated(l))
        # Crawling concurrente para los nuevos links
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            for l in links:
                if l not in self.visited:
                    executor.submit(self._crawl, l, depth+1, max_depth, norm_url)
            # Si hay paginación, seguir solo una rama para evitar loops infinitos
            for p in paginated:
                if p not in self.visited:
                    self._crawl(p, depth+1, max_depth, norm_url)
    def export_tree_visual(self):
        """Exporta el árbol de crawling en formato JSON."""
        import os, json
        os.makedirs(self.report_dir, exist_ok=True)
        tree_path = os.path.join(self.report_dir, "crawl_tree.json")
        with open(tree_path, "w", encoding="utf-8") as f:
            json.dump(self.crawl_tree, f, indent=2, ensure_ascii=False)
        self.logger.info(f"Árbol de crawling exportado en {tree_path}")

    def export_results(self):
        """Exporta los resultados del crawling a JSON, CSV y YAML."""
        if self.exported:
            return
        import os, json
        import csv
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            # Exportar URLs
            with open(os.path.join(self.report_dir, "crawl_urls.json"), "w", encoding="utf-8") as f:
                json.dump(sorted(self.found_urls), f, indent=2, ensure_ascii=False)
            with open(os.path.join(self.report_dir, "crawl_urls.csv"), "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["url"])
                for u in sorted(self.found_urls):
                    writer.writerow([u])
            
            # Exportar formularios
            with open(os.path.join(self.report_dir, "crawl_forms.json"), "w", encoding="utf-8") as f:
                json.dump(self.forms, f, indent=2, ensure_ascii=False)
            
            # Exportar endpoints JS
            with open(os.path.join(self.report_dir, "crawl_js_endpoints.json"), "w", encoding="utf-8") as f:
                json.dump(sorted(self.js_endpoints), f, indent=2, ensure_ascii=False)
            with open(os.path.join(self.report_dir, "crawl_js_endpoints.csv"), "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["endpoint_js"])
                for ep in sorted(self.js_endpoints):
                    writer.writerow([ep])
            
            # Exportar YAML si está disponible
            try:
                import yaml
                with open(os.path.join(self.report_dir, "crawl_urls.yaml"), "w", encoding="utf-8") as f:
                    yaml.dump(sorted(self.found_urls), f, allow_unicode=True)
                with open(os.path.join(self.report_dir, "crawl_forms.yaml"), "w", encoding="utf-8") as f:
                    yaml.dump(self.forms, f, allow_unicode=True)
                with open(os.path.join(self.report_dir, "crawl_js_endpoints.yaml"), "w", encoding="utf-8") as f:
                    yaml.dump(sorted(self.js_endpoints), f, allow_unicode=True)
            except ImportError:
                self.logger.warning("pyyaml no está instalado, no se exporta YAML.")
            except Exception as e:
                self.logger.warning(f"Error exportando YAML: {e}")
            
            self.logger.info(f"Resultados del crawling exportados en {self.report_dir}/")
            self.exported = True
        except Exception as e:
            self.logger.error(f"Error al exportar resultados de crawling: {e}")

    def extract_forms(self, soup, base_url):
        """Extrae formularios y parámetros de una página."""
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(name)
            forms.append({
                "action": urljoin(base_url, action) if action else base_url,
                "method": method,
                "inputs": inputs
            })
        if forms:
            self.logger.info(f"Formularios encontrados en {base_url}: {len(forms)}")
        return forms

    def _is_internal(self, url):
        # Considera interno si el netloc es igual al objetivo
        return urlparse(url).netloc == urlparse(self.target_url).netloc
