#!/usr/bin/env python3
"""
Script de prueba para los módulos CSRF, CORS y LFI/RFI.
Demuestra las nuevas funcionalidades de detección de vulnerabilidades.
"""

from core.scanner import Scanner
from modules.csrf import CSRFModule
from modules.cors import CORSModule
from modules.lfi import LFIModule
from core.logger import get_logger
from datetime import datetime

def test_csrf_cors_lfi():
    """Prueba los módulos CSRF, CORS y LFI."""
    logger = get_logger("test")
    
    # Configuración del escaneo
    target_url = "http://testphp.vulnweb.com"  # Sitio de prueba público
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = f"reports/test_csrf_cors_lfi_{timestamp}"
    
    config = {
        "target_url": target_url,
        "scan_timestamp": timestamp,
        "report_dir": report_dir,
        "export_pdf": False
    }
    
    logger.info("=" * 60)
    logger.info("PRUEBA DE MÓDULOS: CSRF, CORS, LFI/RFI")
    logger.info("=" * 60)
    logger.info(f"Target: {target_url}")
    logger.info(f"Report dir: {report_dir}")
    logger.info("")
    
    # Crear scanner
    scanner = Scanner(target_url, config)
    
    # Registrar módulos
    logger.info("Registrando módulos de seguridad...")
    scanner.register_module(CSRFModule(config))
    scanner.register_module(CORSModule(config))
    scanner.register_module(LFIModule(config))
    
    # Ejecutar escaneo
    logger.info("")
    logger.info("Iniciando escaneo...")
    scanner.run()
    
    # Resumen de resultados
    logger.info("")
    logger.info("=" * 60)
    logger.info("RESUMEN DE RESULTADOS")
    logger.info("=" * 60)
    
    total_findings = len(scanner.all_findings)
    logger.info(f"Total de hallazgos: {total_findings}")
    
    if total_findings > 0:
        by_severity = {}
        for finding in scanner.all_findings:
            severity = finding.get("severity", "info")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        logger.info("")
        logger.info("Por severidad:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                logger.info(f"  {severity.upper()}: {count}")
        
        logger.info("")
        logger.info("Vulnerabilidades encontradas:")
        for finding in scanner.all_findings:
            vuln = finding.get("vulnerability", "Unknown")
            severity = finding.get("severity", "info")
            url = finding.get("url", "")
            logger.info(f"  [{severity.upper()}] {vuln}")
            logger.info(f"    URL: {url}")
    
    logger.info("")
    logger.info(f"Reportes generados en: {report_dir}")
    logger.info("=" * 60)

if __name__ == "__main__":
    test_csrf_cors_lfi()
