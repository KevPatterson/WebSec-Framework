"""
Script de prueba para validar la reducción de falsos positivos.
Prueba los casos más comunes de falsos positivos y verifica que se detecten correctamente.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.validator import Validator
from core.logger import get_logger

logger = get_logger("test_false_positives")


def test_xxe_false_positive_404():
    """Prueba: XXE en endpoint 404 debe tener confianza muy baja."""
    logger.info("=" * 60)
    logger.info("TEST 1: XXE False Positive (404 Page)")
    logger.info("=" * 60)
    
    config = {"target_url": "https://example.com"}
    validator = Validator(config)
    
    # Simular hallazgo XXE con página 404 de Next.js
    finding = {
        "type": "xxe_injection",
        "severity": "critical",
        "title": "XXE en /api/xml",
        "evidence": {
            "url": "https://example.com/api/xml",
            "method": "POST",
            "evidence_found": "<html",
            "response_snippet": "<!DOCTYPE html><html lang=\"es\" class=\"__variable_f367f3 __variable_dd5b2f __variable_0d7163 antialiased \"><head><meta charSet=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width\"/><title>404: This page could not be found</title>",
            "status_code": 404
        }
    }
    
    validated = validator.validate(finding)
    
    logger.info(f"Confianza: {validated['confidence_score']}%")
    logger.info(f"Estado: {validated['validation_status']}")
    logger.info(f"Notas: {validated.get('validation_notes', 'N/A')}")
    
    # Verificar que la confianza sea muy baja
    assert validated['confidence_score'] <= 15, f"Confianza demasiado alta: {validated['confidence_score']}%"
    assert validated['validation_status'] == 'low_confidence', "Debería ser low_confidence"
    
    logger.info("✅ TEST PASADO: Falso positivo XXE detectado correctamente\n")


def test_xxe_real_vulnerability():
    """Prueba: XXE real con /etc/passwd debe tener confianza alta."""
    logger.info("=" * 60)
    logger.info("TEST 2: XXE Real Vulnerability")
    logger.info("=" * 60)
    
    config = {"target_url": "https://example.com"}
    validator = Validator(config)
    
    # Simular hallazgo XXE real con contenido de /etc/passwd
    finding = {
        "type": "xxe_injection",
        "severity": "critical",
        "title": "XXE en /api/xml",
        "evidence": {
            "url": "https://example.com/api/xml",
            "method": "POST",
            "evidence_found": "root:x:0:0:",
            "response_snippet": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "status_code": 200
        }
    }
    
    validated = validator.validate(finding)
    
    logger.info(f"Confianza: {validated['confidence_score']}%")
    logger.info(f"Estado: {validated['validation_status']}")
    logger.info(f"Notas: {validated.get('validation_notes', 'N/A')}")
    
    # Verificar que la confianza sea alta
    assert validated['confidence_score'] >= 80, f"Confianza demasiado baja: {validated['confidence_score']}%"
    assert validated['validation_status'] == 'validated', "Debería ser validated"
    
    logger.info("✅ TEST PASADO: XXE real detectado con alta confianza\n")


def test_csrf_false_positive_404():
    """Prueba: CSRF en endpoint 404 debe tener confianza muy baja."""
    logger.info("=" * 60)
    logger.info("TEST 3: CSRF False Positive (404 Endpoint)")
    logger.info("=" * 60)
    
    config = {"target_url": "https://example.com"}
    validator = Validator(config)
    
    # Simular hallazgo CSRF en endpoint 404
    finding = {
        "type": "csrf_missing_origin_validation",
        "severity": "high",
        "title": "CSRF - Missing Origin Validation",
        "url": "https://example.com/login",
        "method": "POST",
        "details": {
            "malicious_origin": "https://evil.com",
            "status_code": 404,
            "endpoint": "https://example.com/login"
        }
    }
    
    validated = validator.validate(finding)
    
    logger.info(f"Confianza: {validated['confidence_score']}%")
    logger.info(f"Estado: {validated['validation_status']}")
    
    # CSRF con 404 debería tener confianza baja
    assert validated['confidence_score'] <= 65, f"Confianza demasiado alta: {validated['confidence_score']}%"
    
    logger.info("✅ TEST PASADO: CSRF en endpoint 404 tiene confianza apropiada\n")


def test_csrf_real_vulnerability():
    """Prueba: CSRF real debe tener confianza alta."""
    logger.info("=" * 60)
    logger.info("TEST 4: CSRF Real Vulnerability")
    logger.info("=" * 60)
    
    config = {"target_url": "https://example.com"}
    validator = Validator(config)
    
    # Simular hallazgo CSRF real (endpoint responde 200)
    finding = {
        "type": "csrf_missing_origin_validation",
        "severity": "high",
        "title": "CSRF - Missing Origin Validation",
        "url": "https://example.com/api/user/update",
        "method": "POST",
        "details": {
            "malicious_origin": "https://evil.com",
            "status_code": 200,
            "endpoint": "https://example.com/api/user/update"
        }
    }
    
    validated = validator.validate(finding)
    
    logger.info(f"Confianza: {validated['confidence_score']}%")
    logger.info(f"Estado: {validated['validation_status']}")
    
    # CSRF real debería tener confianza alta
    assert validated['confidence_score'] >= 65, f"Confianza demasiado baja: {validated['confidence_score']}%"
    assert validated['validation_status'] == 'validated', "Debería ser validated"
    
    logger.info("✅ TEST PASADO: CSRF real detectado con alta confianza\n")


def test_sqli_with_strong_evidence():
    """Prueba: SQLi con error SQL específico debe tener confianza muy alta."""
    logger.info("=" * 60)
    logger.info("TEST 5: SQLi with Strong Evidence")
    logger.info("=" * 60)
    
    config = {"target_url": "https://example.com"}
    validator = Validator(config)
    
    # Simular hallazgo SQLi con error MySQL específico
    finding = {
        "type": "error_based_sqli",
        "severity": "critical",
        "title": "SQL Injection",
        "url": "https://example.com/page?id=1'",
        "details": {
            "evidence": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            "status_code": 200,
            "type": "error-based",
            "dbms": "MySQL"
        }
    }
    
    validated = validator.validate(finding)
    
    logger.info(f"Confianza: {validated['confidence_score']}%")
    logger.info(f"Estado: {validated['validation_status']}")
    
    # SQLi con error específico debería tener confianza muy alta
    assert validated['confidence_score'] >= 85, f"Confianza demasiado baja: {validated['confidence_score']}%"
    assert validated['validation_status'] == 'validated', "Debería ser validated"
    
    logger.info("✅ TEST PASADO: SQLi con evidencia fuerte detectado correctamente\n")


def test_xss_sanitized():
    """Prueba: XSS con payload sanitizado debe tener confianza baja."""
    logger.info("=" * 60)
    logger.info("TEST 6: XSS with Sanitized Payload")
    logger.info("=" * 60)
    
    config = {"target_url": "https://example.com"}
    validator = Validator(config)
    
    # Simular hallazgo XSS con payload sanitizado
    finding = {
        "type": "reflected_xss",
        "severity": "high",
        "title": "Reflected XSS",
        "url": "https://example.com/search?q=<script>alert(1)</script>",
        "payload": "<script>alert(1)</script>",
        "details": {
            "evidence": "&lt;script&gt;alert(1)&lt;/script&gt;",  # Sanitizado
            "context": "html",
            "type": "reflected"
        }
    }
    
    validated = validator.validate(finding)
    
    logger.info(f"Confianza: {validated['confidence_score']}%")
    logger.info(f"Estado: {validated['validation_status']}")
    logger.info(f"Notas: {validated.get('validation_notes', 'N/A')}")
    
    # XSS sanitizado debería tener confianza baja
    assert validated['confidence_score'] <= 50, f"Confianza demasiado alta: {validated['confidence_score']}%"
    
    logger.info("✅ TEST PASADO: XSS sanitizado detectado como falso positivo\n")


def test_validation_stats():
    """Prueba: Estadísticas de validación."""
    logger.info("=" * 60)
    logger.info("TEST 7: Validation Statistics")
    logger.info("=" * 60)
    
    config = {"target_url": "https://example.com"}
    validator = Validator(config)
    
    # Crear varios hallazgos con diferentes confianzas
    findings = [
        {"confidence_score": 95, "validation_status": "validated"},  # Muy alta
        {"confidence_score": 85, "validation_status": "validated"},  # Alta
        {"confidence_score": 75, "validation_status": "validated"},  # Alta
        {"confidence_score": 65, "validation_status": "validated"},  # Media
        {"confidence_score": 55, "validation_status": "low_confidence"},  # Baja
        {"confidence_score": 10, "validation_status": "low_confidence"},  # Muy baja
    ]
    
    stats = validator.get_validation_stats(findings)
    
    logger.info(f"Total: {stats['total']}")
    logger.info(f"Validados: {stats['validated']}")
    logger.info(f"Baja confianza: {stats['low_confidence']}")
    logger.info(f"Confianza promedio: {stats['avg_confidence']}%")
    logger.info(f"Distribución:")
    logger.info(f"  90-100%: {stats['by_confidence_range']['90-100']}")
    logger.info(f"  70-89%:  {stats['by_confidence_range']['70-89']}")
    logger.info(f"  60-69%:  {stats['by_confidence_range']['60-69']}")
    logger.info(f"  0-59%:   {stats['by_confidence_range']['0-59']}")
    
    # Verificar estadísticas
    assert stats['total'] == 6, "Total incorrecto"
    assert stats['validated'] == 4, "Validados incorrecto"
    assert stats['low_confidence'] == 2, "Baja confianza incorrecto"
    assert stats['by_confidence_range']['90-100'] == 1, "Rango 90-100 incorrecto"
    assert stats['by_confidence_range']['70-89'] == 2, "Rango 70-89 incorrecto"
    
    logger.info("✅ TEST PASADO: Estadísticas calculadas correctamente\n")


def run_all_tests():
    """Ejecuta todos los tests."""
    logger.info("\n" + "=" * 60)
    logger.info("INICIANDO TESTS DE REDUCCIÓN DE FALSOS POSITIVOS")
    logger.info("=" * 60 + "\n")
    
    tests = [
        test_xxe_false_positive_404,
        test_xxe_real_vulnerability,
        test_csrf_false_positive_404,
        test_csrf_real_vulnerability,
        test_sqli_with_strong_evidence,
        test_xss_sanitized,
        test_validation_stats,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            logger.error(f"❌ TEST FALLIDO: {test.__name__}")
            logger.error(f"   Error: {e}\n")
            failed += 1
        except Exception as e:
            logger.error(f"❌ TEST ERROR: {test.__name__}")
            logger.error(f"   Error: {e}\n")
            failed += 1
    
    # Resumen
    logger.info("=" * 60)
    logger.info("RESUMEN DE TESTS")
    logger.info("=" * 60)
    logger.info(f"Total: {len(tests)}")
    logger.info(f"✅ Pasados: {passed}")
    logger.info(f"❌ Fallidos: {failed}")
    logger.info(f"Tasa de éxito: {(passed/len(tests)*100):.1f}%")
    logger.info("=" * 60)
    
    if failed == 0:
        logger.info("\n🎉 TODOS LOS TESTS PASARON EXITOSAMENTE\n")
        return 0
    else:
        logger.error(f"\n⚠️  {failed} TEST(S) FALLARON\n")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
