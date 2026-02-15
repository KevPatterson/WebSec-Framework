"""
Módulo de escaneo de vulnerabilidades. Orquesta módulos independientes.
"""
from core.logger import get_logger
from datetime import datetime
import os
import json


class Scanner:
    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.config["target_url"] = target_url  # Asegurar que el target_url esté en config
        self.modules = []  # Lista de módulos de vulnerabilidades
        self.logger = get_logger("scanner")
        self.all_findings = []
        
        # Timestamp y directorio de reporte compartido
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")
        self.config["scan_timestamp"] = self.scan_timestamp
        self.config["report_dir"] = self.report_dir

    def register_module(self, module):
        """Registra un módulo de vulnerabilidad para ser ejecutado."""
        self.modules.append(module)
        self.logger.info(f"Módulo registrado: {module.__class__.__name__}")

    def run(self):
        """Ejecuta todos los módulos de escaneo registrados."""
        self.logger.info(f"Iniciando escaneo de vulnerabilidades en: {self.target_url}")
        self.logger.info(f"Módulos a ejecutar: {len(self.modules)}")
        
        for module in self.modules:
            try:
                module_name = module.__class__.__name__
                self.logger.info(f"Ejecutando módulo: {module_name}")
                module.scan()
                
                # Recopilar resultados
                if hasattr(module, 'get_results'):
                    findings = module.get_results()
                    if findings:
                        self.all_findings.extend(findings)
                        self.logger.info(f"{module_name}: {len(findings)} hallazgos encontrados")
                
            except Exception as e:
                self.logger.error(f"Error ejecutando módulo {module.__class__.__name__}: {e}")
        
        # Exportar resumen consolidado
        self._export_consolidated_report()
        
        self.logger.info(f"Escaneo completado. Total de hallazgos: {len(self.all_findings)}")

    def _export_consolidated_report(self):
        """Exporta un reporte consolidado de todos los módulos."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            # Agrupar por severidad
            by_severity = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            }
            
            for finding in self.all_findings:
                severity = finding.get("severity", "info")
                by_severity[severity].append(finding)
            
            consolidated = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": self.scan_timestamp,
                    "total_findings": len(self.all_findings),
                    "modules_executed": len(self.modules)
                },
                "summary": {
                    "critical": len(by_severity["critical"]),
                    "high": len(by_severity["high"]),
                    "medium": len(by_severity["medium"]),
                    "low": len(by_severity["low"]),
                    "info": len(by_severity["info"])
                },
                "findings_by_severity": by_severity,
                "all_findings": self.all_findings
            }
            
            # Exportar JSON
            output_path = os.path.join(self.report_dir, "vulnerability_scan_consolidated.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(consolidated, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Reporte consolidado JSON exportado en: {output_path}")
            
            # Generar reporte HTML profesional
            try:
                from core.html_reporter import HTMLReporter
                html_reporter = HTMLReporter(self.config)
                html_path = os.path.join(self.report_dir, "vulnerability_report.html")
                
                # Verificar si se debe exportar a PDF
                export_pdf = self.config.get("export_pdf", False)
                
                if html_reporter.generate(consolidated, html_path, export_pdf=export_pdf):
                    self.logger.info(f"Reporte HTML profesional generado en: {html_path}")
                    
                    if export_pdf:
                        pdf_path = html_path.replace('.html', '.pdf')
                        if os.path.exists(pdf_path):
                            self.logger.info(f"Reporte PDF generado en: {pdf_path}")
                else:
                    self.logger.warning("No se pudo generar el reporte HTML")
            except Exception as e:
                self.logger.error(f"Error generando reporte HTML: {e}")
            
        except Exception as e:
            self.logger.error(f"Error al exportar reporte consolidado: {e}")
