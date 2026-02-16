"""
Script de prueba para las integraciones externas (SQLMap y ZAP)
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from core.external.sqlmap_runner import SqlmapRunner
from core.external.zap_runner import ZapRunner
from core.logger import get_logger

logger = get_logger("test_external")

def test_sqlmap():
    """Prueba la integración de SQLMap"""
    logger.info("=" * 60)
    logger.info("PRUEBA: SQLMap Runner")
    logger.info("=" * 60)
    
    config = {
        "sqlmap_path": "sqlmap",
        "sqlmap_timeout": 120
    }
    
    runner = SqlmapRunner(config)
    
    # Test 1: Verificar detección de binario
    logger.info("\n[Test 1] Verificando detección de binario SQLMap...")
    sqlmap_exec, bin_name, is_python = runner._find_sqlmap_exec()
    if sqlmap_exec:
        logger.info(f"✓ SQLMap encontrado: {sqlmap_exec} (Python: {is_python})")
    else:
        logger.warning(f"✗ SQLMap no encontrado. Instálalo desde https://github.com/sqlmapproject/sqlmap")
        logger.info(f"  Buscando: {bin_name}")
        return False
    
    # Test 2: Ejecutar escaneo de prueba (solo si está instalado)
    logger.info("\n[Test 2] Ejecutando escaneo de prueba...")
    logger.info("Target: http://testphp.vulnweb.com/artists.php?artist=1")
    
    try:
        findings = runner.run(
            target="http://testphp.vulnweb.com/artists.php?artist=1",
            risk=1,
            level=1,
            threads=1,
            timeout=60
        )
        
        logger.info(f"✓ Escaneo completado. Hallazgos: {len(findings)}")
        
        if findings:
            logger.info("\nPrimeros hallazgos:")
            for i, finding in enumerate(findings[:3], 1):
                logger.info(f"  {i}. {finding.get('type', 'Unknown')}: {finding.get('description', 'N/A')[:80]}")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Error en escaneo: {e}")
        return False

def test_zap():
    """Prueba la integración de ZAP"""
    logger.info("\n" + "=" * 60)
    logger.info("PRUEBA: ZAP Runner")
    logger.info("=" * 60)
    
    config = {
        "zap_path": "zap.sh",
        "zap_timeout": 120,
        "zap_api_port": 8090
    }
    
    runner = ZapRunner(config)
    
    # Test 1: Verificar detección de binario
    logger.info("\n[Test 1] Verificando detección de binario ZAP...")
    zap_exec, bin_name = runner._find_zap_exec()
    if zap_exec:
        logger.info(f"✓ ZAP encontrado: {zap_exec}")
    else:
        logger.warning(f"✗ ZAP no encontrado. Instálalo desde https://www.zaproxy.org/download/")
        logger.info(f"  Buscando: {bin_name}")
        return False
    
    # Test 2: Ejecutar escaneo de prueba (solo si está instalado)
    logger.info("\n[Test 2] Ejecutando escaneo de prueba...")
    logger.info("Target: http://testphp.vulnweb.com/")
    
    try:
        findings = runner.run(
            target="http://testphp.vulnweb.com/",
            scan_mode="quick",
            output_format="json",
            timeout=60
        )
        
        logger.info(f"✓ Escaneo completado. Hallazgos: {len(findings)}")
        
        if findings:
            logger.info("\nPrimeros hallazgos:")
            for i, finding in enumerate(findings[:3], 1):
                logger.info(f"  {i}. {finding.get('type', 'Unknown')} [{finding.get('severity', 'N/A')}]")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Error en escaneo: {e}")
        return False

def test_integration():
    """Prueba la integración completa"""
    logger.info("\n" + "=" * 60)
    logger.info("PRUEBA: Integración Completa")
    logger.info("=" * 60)
    
    # Configuración combinada
    config = {
        "sqlmap_path": "sqlmap",
        "sqlmap_timeout": 60,
        "zap_path": "zap.sh",
        "zap_timeout": 60
    }
    
    sqlmap_runner = SqlmapRunner(config)
    zap_runner = ZapRunner(config)
    
    target = "http://testphp.vulnweb.com/"
    
    logger.info(f"\nTarget: {target}")
    logger.info("Ejecutando ambas herramientas en paralelo (simulado)...")
    
    all_findings = []
    
    # SQLMap
    sqlmap_exec, _, _ = sqlmap_runner._find_sqlmap_exec()
    if sqlmap_exec:
        logger.info("\n[SQLMap] Iniciando escaneo...")
        try:
            sqlmap_findings = sqlmap_runner.run(
                target=target + "artists.php?artist=1",
                risk=1,
                level=1,
                timeout=30
            )
            all_findings.extend(sqlmap_findings)
            logger.info(f"[SQLMap] Completado: {len(sqlmap_findings)} hallazgos")
        except Exception as e:
            logger.error(f"[SQLMap] Error: {e}")
    else:
        logger.warning("[SQLMap] No disponible")
    
    # ZAP
    zap_exec, _ = zap_runner._find_zap_exec()
    if zap_exec:
        logger.info("\n[ZAP] Iniciando escaneo...")
        try:
            zap_findings = zap_runner.run(
                target=target,
                scan_mode="quick",
                timeout=30
            )
            all_findings.extend(zap_findings)
            logger.info(f"[ZAP] Completado: {len(zap_findings)} hallazgos")
        except Exception as e:
            logger.error(f"[ZAP] Error: {e}")
    else:
        logger.warning("[ZAP] No disponible")
    
    # Resumen
    logger.info("\n" + "=" * 60)
    logger.info(f"RESUMEN: Total de hallazgos: {len(all_findings)}")
    logger.info("=" * 60)
    
    if all_findings:
        # Agrupar por severidad
        by_severity = {}
        for finding in all_findings:
            sev = finding.get('severity', 'unknown')
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        logger.info("\nPor severidad:")
        for sev, count in sorted(by_severity.items()):
            logger.info(f"  {sev}: {count}")
    
    return len(all_findings) > 0

if __name__ == "__main__":
    logger.info("Iniciando pruebas de integraciones externas...")
    logger.info("Nota: Estas pruebas requieren que SQLMap y/o ZAP estén instalados")
    logger.info("")
    
    results = {
        "SQLMap": False,
        "ZAP": False,
        "Integration": False
    }
    
    # Ejecutar pruebas
    try:
        results["SQLMap"] = test_sqlmap()
    except Exception as e:
        logger.error(f"Error en prueba SQLMap: {e}")
    
    try:
        results["ZAP"] = test_zap()
    except Exception as e:
        logger.error(f"Error en prueba ZAP: {e}")
    
    try:
        results["Integration"] = test_integration()
    except Exception as e:
        logger.error(f"Error en prueba de integración: {e}")
    
    # Reporte final
    logger.info("\n" + "=" * 60)
    logger.info("REPORTE FINAL")
    logger.info("=" * 60)
    
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL/SKIP"
        logger.info(f"{test_name}: {status}")
    
    logger.info("\nNota: Los tests pueden fallar si las herramientas no están instaladas.")
    logger.info("Esto es normal y no indica un problema con el código.")
