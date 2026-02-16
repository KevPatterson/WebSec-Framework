"""
Script de prueba rápida para el módulo XXE.
"""

import sys
import os

# Añadir el directorio raíz al path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.xxe import XXEModule
from core.logger import get_logger

logger = get_logger("test_xxe")

def test_xxe_module():
    """Prueba el módulo XXE."""
    
    logger.info("=" * 70)
    logger.info("PRUEBA DEL MÓDULO XXE")
    logger.info("=" * 70)
    
    # URL de prueba
    target_url = "http://testphp.vulnweb.com/"
    
    # Configuración
    config = {
        "target_url": target_url,
        "timeout": 10,
        "enable_validation": False
    }
    
    try:
        # Crear instancia del módulo
        logger.info(f"Target: {target_url}")
        xxe_module = XXEModule(config)
        
        # Verificar atributos
        logger.info(f"Módulo creado: {xxe_module.__class__.__name__}")
        logger.info(f"Payloads disponibles: {len(xxe_module.BASIC_PAYLOADS)}")
        logger.info(f"Patrones de evidencia: {len(xxe_module.XXE_EVIDENCE_PATTERNS)}")
        
        # Ejecutar escaneo
        logger.info("\nIniciando escaneo XXE...")
        xxe_module.scan()
        
        # Obtener resultados
        findings = xxe_module.get_results()
        
        logger.info("\n" + "=" * 70)
        logger.info("RESULTADOS")
        logger.info("=" * 70)
        logger.info(f"Total de hallazgos: {len(findings)}")
        
        if findings:
            for i, finding in enumerate(findings, 1):
                logger.info(f"\n[{i}] {finding.get('title', 'Sin título')}")
                logger.info(f"    Severidad: {finding.get('severity', 'N/A')}")
                logger.info(f"    CVSS: {finding.get('cvss', 'N/A')}")
                logger.info(f"    CWE: {finding.get('cwe', 'N/A')}")
        else:
            logger.info("No se encontraron vulnerabilidades XXE (esperado en este target)")
        
        logger.info("\n✅ Prueba del módulo XXE completada exitosamente")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error durante la prueba: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_xxe_module()
    sys.exit(0 if success else 1)
