"""
Módulo de escaneo de vulnerabilidades. Orquesta módulos independientes.
"""
from core.logger import get_logger
from core.validator import Validator
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
        
        # Inicializar validador
        self.validator = Validator(config)
        self.enable_validation = config.get("enable_validation", True)

    def register_module(self, module):
        """Registra un módulo de vulnerabilidad para ser ejecutado."""
        self.modules.append(module)
        self.logger.info(f"Módulo registrado: {module.__class__.__name__}")

    def run(self):
        """Ejecuta todos los módulos de escaneo registrados."""
        self.logger.info(f"Iniciando escaneo de vulnerabilidades en: {self.target_url}")
        self.logger.info(f"Módulos a ejecutar: {len(self.modules)}")
        self.logger.info(f"Validación habilitada: {self.enable_validation}")
        
        for module in self.modules:
            try:
                module_name = module.__class__.__name__
                self.logger.info(f"Ejecutando módulo: {module_name}")
                module.scan()
                
                # Recopilar resultados
                if hasattr(module, 'get_results'):
                    findings = module.get_results()
                    if findings:
                        # Validar hallazgos si está habilitado
                        if self.enable_validation:
                            self.logger.info(f"Validando {len(findings)} hallazgos de {module_name}...")
                            findings = self.validator.validate_batch(findings)
                        
                        self.all_findings.extend(findings)
                        self.logger.info(f"{module_name}: {len(findings)} hallazgos encontrados")
                
            except Exception as e:
                self.logger.error(f"Error ejecutando módulo {module.__class__.__name__}: {e}")
        
        # Exportar resumen consolidado
        self._export_consolidated_report()
        
        # Mostrar estadísticas de validación
        if self.enable_validation and self.all_findings:
            self._show_validation_stats()
        
        self.logger.info(f"Escaneo completado. Total de hallazgos: {len(self.all_findings)}")

    def _show_validation_stats(self):
        """Muestra estadísticas de validación."""
        stats = self.validator.get_validation_stats(self.all_findings)
        
        self.logger.info("=" * 60)
        self.logger.info("ESTADÍSTICAS DE VALIDACIÓN")
        self.logger.info("=" * 60)
        self.logger.info(f"Total de hallazgos: {stats['total']}")
        self.logger.info(f"Validados (confianza >= 60): {stats['validated']}")
        self.logger.info(f"Baja confianza (< 60): {stats['low_confidence']}")
        self.logger.info(f"Confianza promedio: {stats['avg_confidence']}%")
        self.logger.info("")
        self.logger.info("Distribución por confianza:")
        self.logger.info(f"  90-100% (Muy alta): {stats['by_confidence_range']['90-100']}")
        self.logger.info(f"  70-89%  (Alta):     {stats['by_confidence_range']['70-89']}")
        self.logger.info(f"  60-69%  (Media):    {stats['by_confidence_range']['60-69']}")
        self.logger.info(f"  0-59%   (Baja):     {stats['by_confidence_range']['0-59']}")
        self.logger.info("=" * 60)

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
            
            # Agrupar por confianza si la validación está habilitada
            by_confidence = {
                "high": [],      # 90-100
                "medium": [],    # 70-89
                "low": [],       # 60-69
                "very_low": []   # 0-59
            }
            
            for finding in self.all_findings:
                severity = finding.get("severity", "info")
                by_severity[severity].append(finding)
                
                # Clasificar por confianza
                if self.enable_validation:
                    confidence = finding.get('confidence_score', 0)
                    if confidence >= 90:
                        by_confidence['high'].append(finding)
                    elif confidence >= 70:
                        by_confidence['medium'].append(finding)
                    elif confidence >= 60:
                        by_confidence['low'].append(finding)
                    else:
                        by_confidence['very_low'].append(finding)
            
            consolidated = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": self.scan_timestamp,
                    "total_findings": len(self.all_findings),
                    "modules_executed": len(self.modules),
                    "validation_enabled": self.enable_validation
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
            
            # Añadir estadísticas de validación si está habilitada
            if self.enable_validation:
                validation_stats = self.validator.get_validation_stats(self.all_findings)
                consolidated["validation_stats"] = validation_stats
                consolidated["findings_by_confidence"] = by_confidence
            
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
