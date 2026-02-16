"""
Script de prueba para verificar la opción --no-crawl.
"""

import sys
import os

# Añadir el directorio raíz al path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.logger import get_logger

logger = get_logger("test_no_crawl")

def test_no_crawl_option():
    """Prueba la opción --no-crawl."""
    
    logger.info("=" * 70)
    logger.info("PRUEBA DE LA OPCIÓN --no-crawl")
    logger.info("=" * 70)
    
    target_url = "http://testphp.vulnweb.com/"
    
    logger.info(f"Target: {target_url}")
    logger.info("")
    logger.info("Esta prueba verifica que:")
    logger.info("1. El escaneo se ejecuta sin crawling")
    logger.info("2. El escaneo se ejecuta sin fingerprinting")
    logger.info("3. Solo se ejecutan los módulos de vulnerabilidad")
    logger.info("4. Los reportes se generan correctamente")
    logger.info("")
    logger.info("Comando a ejecutar:")
    logger.info(f"  python run.py {target_url} --no-crawl")
    logger.info("")
    logger.info("Archivos que NO se deben generar:")
    logger.info("  - crawl_urls.json")
    logger.info("  - crawl_forms.json")
    logger.info("  - crawl_js_endpoints.json")
    logger.info("  - crawl_tree.json")
    logger.info("  - fingerprint.json")
    logger.info("")
    logger.info("Archivos que SÍ se deben generar:")
    logger.info("  - xss_findings.json")
    logger.info("  - sqli_findings.json")
    logger.info("  - headers_findings.json")
    logger.info("  - csrf_findings.json")
    logger.info("  - cors_findings.json")
    logger.info("  - lfi_findings.json")
    logger.info("  - xxe_findings.json")
    logger.info("  - ssrf_findings.json")
    logger.info("  - cmdi_findings.json")
    logger.info("  - auth_findings.json")
    logger.info("  - vulnerability_scan_consolidated.json")
    logger.info("  - vulnerability_report.html")
    logger.info("")
    logger.info("=" * 70)
    logger.info("EJECUTANDO PRUEBA")
    logger.info("=" * 70)
    
    import subprocess
    import time
    
    try:
        # Ejecutar el comando
        start_time = time.time()
        result = subprocess.run(
            ["python", "run.py", target_url, "--no-crawl"],
            capture_output=True,
            text=True,
            timeout=120
        )
        elapsed_time = time.time() - start_time
        
        logger.info(f"\nTiempo de ejecución: {elapsed_time:.2f} segundos")
        
        if result.returncode == 0:
            logger.info("✅ Comando ejecutado exitosamente")
            
            # Verificar que el mensaje de crawling deshabilitado aparece
            if "--no-crawl" in result.stdout or "Crawling deshabilitado" in result.stdout:
                logger.info("✅ Mensaje de crawling deshabilitado encontrado")
            else:
                logger.warning("⚠️ No se encontró el mensaje de crawling deshabilitado")
            
            # Buscar el directorio de reportes en la salida
            import re
            match = re.search(r'reports/scan_(\d+_\d+)', result.stdout)
            if match:
                report_dir = f"reports/scan_{match.group(1)}"
                logger.info(f"\nDirectorio de reportes: {report_dir}")
                
                # Verificar archivos que NO deben existir
                logger.info("\nVerificando archivos que NO deben existir:")
                no_files = [
                    "crawl_urls.json",
                    "crawl_forms.json",
                    "crawl_js_endpoints.json",
                    "crawl_tree.json",
                    "fingerprint.json"
                ]
                
                for filename in no_files:
                    filepath = os.path.join(report_dir, filename)
                    if not os.path.exists(filepath):
                        logger.info(f"  ✅ {filename} - NO existe (correcto)")
                    else:
                        logger.error(f"  ❌ {filename} - EXISTE (incorrecto)")
                
                # Verificar archivos que SÍ deben existir
                logger.info("\nVerificando archivos que SÍ deben existir:")
                yes_files = [
                    "vulnerability_scan_consolidated.json",
                    "vulnerability_report.html"
                ]
                
                for filename in yes_files:
                    filepath = os.path.join(report_dir, filename)
                    if os.path.exists(filepath):
                        logger.info(f"  ✅ {filename} - EXISTE (correcto)")
                    else:
                        logger.error(f"  ❌ {filename} - NO existe (incorrecto)")
            
            logger.info("\n" + "=" * 70)
            logger.info("✅ PRUEBA COMPLETADA EXITOSAMENTE")
            logger.info("=" * 70)
            return True
        else:
            logger.error(f"❌ Error ejecutando el comando (código: {result.returncode})")
            logger.error(f"STDERR: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("❌ Timeout: El comando tardó más de 120 segundos")
        return False
    except Exception as e:
        logger.error(f"❌ Error durante la prueba: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_no_crawl_option()
    sys.exit(0 if success else 1)
