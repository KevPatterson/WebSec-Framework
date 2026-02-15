"""
Módulo de generación de reportes profesionales (HTML/JSON).
"""


import os
import json
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
from core.logger import get_logger

class Reporter:
    def __init__(self, config):
        self.config = config
        self.logger = get_logger("reporter")
        self.env = Environment(
            loader=FileSystemLoader(self._get_templates_dir()),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def generate(self, findings, output_dir=None, target_url=None, scan_timestamp=None):
        """Genera un reporte profesional en HTML y JSON."""
        if not findings:
            self.logger.warning("No hay hallazgos para reportar.")
            return
        
        # Si no se proporciona output_dir, crear uno con timestamp
        if output_dir is None:
            if scan_timestamp is None:
                scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"reports/scan_{scan_timestamp}"
        
        os.makedirs(output_dir, exist_ok=True)
        
        # HTML
        html_path = os.path.join(output_dir, "vulnerability_report.html")
        self._generate_html(findings, html_path, target_url)
        # JSON
        json_path = os.path.join(output_dir, "vulnerability_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        self.logger.info(f"Reporte generado: {html_path} y {json_path}")

    def _generate_html(self, findings, html_path, target_url):
        template = self.env.get_template("report_template.html")
        rendered = template.render(
            findings=findings,
            target_url=target_url,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(rendered)

    def _get_templates_dir(self):
        # Busca la carpeta de plantillas en core/templates o templates/
        base = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(base, "templates"),
            os.path.join(base, "..", "templates"),
        ]
        for c in candidates:
            if os.path.isdir(c):
                return c
        raise FileNotFoundError("No se encontró carpeta de plantillas para reportes.")
