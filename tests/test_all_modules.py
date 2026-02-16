"""
Script de prueba para verificar todos los módulos de vulnerabilidad.
Prueba: XSS, SQLi, Headers, CSRF, CORS, LFI, XXE, SSRF, Command Injection, Auth
"""

import sys
import os

# Añadir el directorio raíz al path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.scanner import Scanner
from core.crawler import Crawler
from core.fingerprint import Fingerprinter
from modules.xss import XSSModule
from modules.sqli import SQLiModule
from modules.headers import HeadersModule
from modules.csrf import CSRFModule
from modules.cors import CORSModule
from modules.lfi import LFIModule
from modules.xxe import XXEModule
from modules.ssrf import SSRFModule
from modules.cmdi import CommandInjectionModule
from modules.auth import AuthModule
from core.logger import get_logger

logger = get_logger("test_all_modules")

def test_all_modules():
    """Prueba todos los módulos de vulnerabilidad."""
    
    # URL de prueba (sitio vulnerable conocido)
    target_url = "http://testphp.vulnweb.com/"
    
    logger.info("=" * 70)
    logger.info("PRUEBA COMPLETA DE TODOS LOS MÓDULOS")
    logger.info("=" * 70)
    logger.info(f"Target: {target_url}")
    logger.info("")
    
    # Configuración
    config = {
        "target_url": target_url,
        "max_depth": 2,
        "max_urls": 20,
        "timeout": 10,
        "enable_validation": True,
        "export_pdf": False
    }
    
    try:
        # 1. Crawling
        logger.info("[1/3] Iniciando crawling...")
        crawler = Crawler(target_url, config)
        crawler.crawl()
        crawl_results = crawler.get_results()
        logger.info(f"Crawling completado: {len(crawl_results.get('urls', []))} URLs encontradas")
        
        # 2. Fingerprinting
        logger.info("\n[2/3] Iniciando fingerprinting...")
        fingerprinter = Fingerprinter(target_url, config)
        fingerprinter.run()
        fingerprint_results = fingerprinter.get_results()
        logger.info(f"Fingerprinting completado")
        
        # 3. Escaneo de vulnerabilidades
        logger.info("\n[3/3] Iniciando escaneo de vulnerabilidades...")
        logger.info("Módulos a probar:")
        logger.info("  - XSS (Cross-Site Scripting)")
        logger.info("  - SQLi (SQL Injection)")
        logger.info("  - Headers (Security Headers)")
        logger.info("  - CSRF (Cross-Site Request Forgery)")
        logger.info("  - CORS (Cross-Origin Resource Sharing)")
        logger.info("  - LFI (Local File Inclusion)")
        logger.info("  - XXE (XML External Entity)")
        logger.info("  - SSRF (Server-Side Request Forgery)")
        logger.info("  - CMDI (Command Injection)")
        logger.info("  - AUTH (Authentication)")
        logger.info("")
        
        scanner = Scanner(target_url, config)
        
        # Registrar todos los módulos
        scanner.register_module(XSSModule(config))
        scanner.register_module(SQLiModule(config))
        scanner.register_module(HeadersModule(config))
        scanner.register_module(CSRFModule(config))
        scanner.register_module(CORSModule(config))
        scanner.register_module(LFIModule(config))
        scanner.register_module(XXEModule(config))
        scanner.register_module(SSRFModule(config))
        scanner.register_module(CommandInjectionModule(config))
        scanner.register_module(AuthModule(config))
        
        # Ejecutar escaneo
        scanner.run()
        
        # Resumen final
        logger.info("")
        logger.info("=" * 70)
        logger.info("RESUMEN FINAL")
        logger.info("=" * 70)
        logger.info(f"Total de hallazgos: {len(scanner.all_findings)}")
        
        # Agrupar por severidad
        by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in scanner.all_findings:
            severity = finding.get("severity", "info")
            by_severity[severity] += 1
        
        logger.info(f"  Critical: {by_severity['critical']}")
        logger.info(f"  High:     {by_severity['high']}")
        logger.info(f"  Medium:   {by_severity['medium']}")
        logger.info(f"  Low:      {by_severity['low']}")
        logger.info(f"  Info:     {by_severity['info']}")
        
        # Agrupar por tipo
        by_type = {}
        for finding in scanner.all_findings:
            finding_type = finding.get("type", "unknown")
            by_type[finding_type] = by_type.get(finding_type, 0) + 1
        
        logger.info("")
        logger.info("Hallazgos por tipo:")
        for finding_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"  {finding_type}: {count}")
        
        logger.info("")
        logger.info(f"Reportes generados en: {scanner.report_dir}")
        logger.info("=" * 70)
        
        return True
        
    except Exception as e:
        logger.error(f"Error durante la prueba: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_all_modules()
    sys.exit(0 if success else 1)
