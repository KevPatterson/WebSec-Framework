"""
Generador de reportes HTML profesionales.
Estilo Acunetix/Burp Suite con dashboard, gráficos y exportación a PDF.
"""

import json
import os
from datetime import datetime
from jinja2 import Template
from core.logger import get_logger
from core.pdf_exporter import PDFExporter


class HTMLReporter:
    """Genera reportes HTML profesionales con dashboard y gráficos."""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = get_logger("html_reporter")
        self.pdf_exporter = PDFExporter()
    
    def generate(self, consolidated_data, output_path, export_pdf=False):
        """
        Genera un reporte HTML profesional.
        
        Args:
            consolidated_data: Dict con los datos del escaneo
            output_path: Ruta donde guardar el HTML
            export_pdf: Si True, también genera un PDF
        """
        try:
            self.logger.info(f"Generando reporte HTML en: {output_path}")
            
            # Cargar template
            template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'professional_report.html')
            
            if not os.path.exists(template_path):
                self.logger.error(f"Template no encontrado: {template_path}")
                return False
            
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            template = Template(template_content)
            
            # Preparar datos para el template
            report_data = self._prepare_report_data(consolidated_data)
            
            # Renderizar HTML
            html_content = template.render(**report_data)
            
            # Guardar archivo
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Reporte HTML generado exitosamente: {output_path}")
            
            # Exportar a PDF si se solicita
            if export_pdf:
                pdf_path = output_path.replace('.html', '.pdf')
                if self.export_to_pdf(output_path, pdf_path):
                    self.logger.info(f"Reporte PDF generado: {pdf_path}")
                else:
                    self.logger.warning("No se pudo generar el PDF")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error generando reporte HTML: {e}")
            return False
    
    def _prepare_report_data(self, data):
        """Prepara los datos para el template."""
        scan_info = data.get('scan_info', {})
        summary = data.get('summary', {})
        findings = data.get('all_findings', [])
        
        # Calcular estadísticas
        total_findings = len(findings)
        
        # Agrupar por severidad
        by_severity = {
            'critical': [f for f in findings if f.get('severity') == 'critical'],
            'high': [f for f in findings if f.get('severity') == 'high'],
            'medium': [f for f in findings if f.get('severity') == 'medium'],
            'low': [f for f in findings if f.get('severity') == 'low'],
            'info': [f for f in findings if f.get('severity') == 'info']
        }
        
        # Agrupar por tipo
        by_type = {}
        for finding in findings:
            ftype = finding.get('type', 'unknown')
            if ftype not in by_type:
                by_type[ftype] = []
            by_type[ftype].append(finding)
        
        # Calcular score de riesgo (0-100)
        risk_score = self._calculate_risk_score(summary)
        
        # Timeline (simulado por ahora)
        timeline = self._generate_timeline(scan_info)
        
        return {
            'scan_info': scan_info,
            'summary': summary,
            'findings': findings,
            'by_severity': by_severity,
            'by_type': by_type,
            'total_findings': total_findings,
            'risk_score': risk_score,
            'timeline': timeline,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _calculate_risk_score(self, summary):
        """Calcula un score de riesgo de 0-100."""
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        medium = summary.get('medium', 0)
        low = summary.get('low', 0)
        
        # Ponderación: Critical=40, High=25, Medium=15, Low=5
        score = (critical * 40) + (high * 25) + (medium * 15) + (low * 5)
        
        # Normalizar a 0-100
        max_score = 500  # Asumiendo máximo razonable
        normalized = min(100, (score / max_score) * 100)
        
        return round(normalized, 1)
    
    def _generate_timeline(self, scan_info):
        """Genera timeline del escaneo."""
        timestamp = scan_info.get('timestamp', '')
        
        # Parsear timestamp
        try:
            dt = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
            start_time = dt.strftime('%H:%M:%S')
        except:
            start_time = '00:00:00'
        
        # Timeline simulado (en producción vendría de logs reales)
        timeline = [
            {'time': start_time, 'event': 'Escaneo iniciado', 'type': 'start'},
            {'time': start_time, 'event': 'Crawling completado', 'type': 'info'},
            {'time': start_time, 'event': 'Fingerprinting completado', 'type': 'info'},
            {'time': start_time, 'event': 'Análisis de vulnerabilidades completado', 'type': 'success'},
            {'time': start_time, 'event': 'Reporte generado', 'type': 'end'}
        ]
        
        return timeline

    def export_to_pdf(self, html_path, pdf_path):
        """
        Exporta el reporte HTML a PDF.
        
        Args:
            html_path: Ruta del archivo HTML
            pdf_path: Ruta donde guardar el PDF
        
        Returns:
            bool: True si la exportación fue exitosa
        """
        if not self.pdf_exporter.is_available():
            self.logger.warning("wkhtmltopdf no está disponible")
            self.logger.info(self.pdf_exporter.get_installation_instructions())
            return False
        
        # Opciones específicas para el reporte
        options = {
            "page-size": "A4",
            "margin-top": "15mm",
            "margin-right": "15mm",
            "margin-bottom": "15mm",
            "margin-left": "15mm",
            "encoding": "UTF-8",
            "enable-local-file-access": None,
            "print-media-type": None,
            "no-stop-slow-scripts": None,
            "javascript-delay": "2000",  # Esperar a que se carguen los gráficos
            "enable-javascript": None
        }
        
        return self.pdf_exporter.export(html_path, pdf_path, options)
