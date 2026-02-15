#!/usr/bin/env python3
"""
Script de prueba para el sistema de validación.
Demuestra comparación de respuestas baseline, detección de falsos positivos
y scoring de confianza.
"""

from core.validator import Validator
from core.logger import get_logger
import json

def test_validation_system():
    """Prueba el sistema de validación con hallazgos de ejemplo."""
    logger = get_logger("test_validation")
    
    logger.info("=" * 80)
    logger.info("PRUEBA DEL SISTEMA DE VALIDACIÓN")
    logger.info("=" * 80)
    
    # Configuración
    config = {
        "target_url": "http://testphp.vulnweb.com",
        "filter_low_confidence": False  # Mostrar todos los hallazgos
    }
    
    # Crear validador
    validator = Validator(config)
    
    # Hallazgos de prueba
    test_findings = [
        # SQLi con evidencia fuerte
        {
            "vulnerability": "SQLi - Error-based",
            "severity": "critical",
            "cvss_score": 9.8,
            "url": "http://testphp.vulnweb.com/artists.php?artist=1'",
            "method": "GET",
            "parameter": "artist",
            "payload": "1'",
            "details": {
                "type": "error-based",
                "dbms": "MySQL",
                "evidence": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
                "status_code": 200
            }
        },
        
        # SQLi sin evidencia clara (posible falso positivo)
        {
            "vulnerability": "SQLi - Boolean-based",
            "severity": "high",
            "cvss_score": 8.6,
            "url": "http://testphp.vulnweb.com/search.php?q=test",
            "method": "GET",
            "parameter": "q",
            "payload": "test' AND '1'='1",
            "details": {
                "type": "boolean-based",
                "evidence": "",
                "status_code": 200
            }
        },
        
        # XSS reflejado con payload sanitizado (falso positivo)
        {
            "vulnerability": "XSS - Reflected",
            "severity": "high",
            "cvss_score": 7.1,
            "url": "http://testphp.vulnweb.com/search.php?q=<script>alert(1)</script>",
            "method": "GET",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "details": {
                "type": "reflected",
                "context": "html",
                "evidence": "&lt;script&gt;alert(1)&lt;/script&gt;"
            }
        },
        
        # XSS con payload reflejado sin sanitización
        {
            "vulnerability": "XSS - Reflected",
            "severity": "high",
            "cvss_score": 7.1,
            "url": "http://testphp.vulnweb.com/comment.php?name=<script>alert(1)</script>",
            "method": "GET",
            "parameter": "name",
            "payload": "<script>alert(1)</script>",
            "details": {
                "type": "reflected",
                "context": "script",
                "evidence": "<script>alert(1)</script>"
            }
        },
        
        # LFI con evidencia de /etc/passwd
        {
            "vulnerability": "LFI - Local File Inclusion",
            "severity": "high",
            "cvss_score": 7.5,
            "url": "http://testphp.vulnweb.com/file.php?path=../../../etc/passwd",
            "method": "GET",
            "parameter": "path",
            "payload": "../../../etc/passwd",
            "details": {
                "evidence": ["root:x:0:0:root:/root:/bin/bash", "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"]
            }
        },
        
        # CSRF - Missing Token (alta confianza)
        {
            "vulnerability": "CSRF - Missing Token",
            "severity": "high",
            "cvss_score": 8.8,
            "url": "http://testphp.vulnweb.com/login",
            "method": "POST",
            "details": {
                "form_action": "/login",
                "form_method": "POST"
            }
        },
        
        # CORS - Wildcard con credentials (crítico)
        {
            "vulnerability": "CORS - Origin Reflection with Credentials",
            "severity": "critical",
            "cvss_score": 9.1,
            "url": "http://testphp.vulnweb.com/api/data",
            "details": {
                "tested_origin": "https://evil.com",
                "reflected_origin": "https://evil.com",
                "credentials": "true"
            }
        }
    ]
    
    logger.info(f"\nValidando {len(test_findings)} hallazgos de prueba...\n")
    
    # Validar hallazgos
    validated_findings = validator.validate_batch(test_findings)
    
    # Mostrar resultados
    logger.info("=" * 80)
    logger.info("RESULTADOS DE VALIDACIÓN")
    logger.info("=" * 80)
    
    for i, finding in enumerate(validated_findings, 1):
        vuln = finding.get('vulnerability', 'Unknown')
        confidence = finding.get('confidence_score', 0)
        status = finding.get('validation_status', 'unknown')
        url = finding.get('url', '')
        
        # Emoji según confianza
        if confidence >= 90:
            emoji = "🟢"
        elif confidence >= 70:
            emoji = "🟡"
        elif confidence >= 60:
            emoji = "🟠"
        else:
            emoji = "🔴"
        
        logger.info(f"\n{i}. {vuln}")
        logger.info(f"   URL: {url}")
        logger.info(f"   {emoji} Confianza: {confidence}% ({status})")
        
        # Mostrar notas de validación si existen
        if finding.get('validation_notes'):
            logger.info(f"   📝 Nota: {finding['validation_notes']}")
        
        # Mostrar comparación baseline si existe
        if finding.get('validation', {}).get('baseline_comparison'):
            comparison = finding['validation']['baseline_comparison']
            if comparison.get('significant_diff'):
                logger.info(f"   ✓ Diferencia significativa detectada vs baseline")
    
    # Estadísticas
    logger.info("\n" + "=" * 80)
    logger.info("ESTADÍSTICAS DE VALIDACIÓN")
    logger.info("=" * 80)
    
    stats = validator.get_validation_stats(validated_findings)
    
    logger.info(f"\nTotal de hallazgos: {stats['total']}")
    logger.info(f"Validados (confianza >= 60): {stats['validated']}")
    logger.info(f"Baja confianza (< 60): {stats['low_confidence']}")
    logger.info(f"Confianza promedio: {stats['avg_confidence']}%")
    
    logger.info("\nDistribución por confianza:")
    logger.info(f"  🟢 90-100% (Muy alta): {stats['by_confidence_range']['90-100']}")
    logger.info(f"  🟡 70-89%  (Alta):     {stats['by_confidence_range']['70-89']}")
    logger.info(f"  🟠 60-69%  (Media):    {stats['by_confidence_range']['60-69']}")
    logger.info(f"  🔴 0-59%   (Baja):     {stats['by_confidence_range']['0-59']}")
    
    # Exportar resultados
    output_file = "reports/validation_test_results.json"
    try:
        import os
        os.makedirs("reports", exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'validated_findings': validated_findings,
                'statistics': stats
            }, f, indent=2, ensure_ascii=False)
        
        logger.info(f"\n📁 Resultados exportados a: {output_file}")
    except Exception as e:
        logger.error(f"Error exportando resultados: {e}")
    
    logger.info("\n" + "=" * 80)

def test_baseline_comparison():
    """Prueba la comparación de respuestas baseline."""
    logger = get_logger("test_baseline")
    
    logger.info("\n" + "=" * 80)
    logger.info("PRUEBA DE COMPARACIÓN BASELINE")
    logger.info("=" * 80)
    
    config = {"target_url": "http://testphp.vulnweb.com"}
    validator = Validator(config)
    
    # Obtener baseline
    test_url = "http://testphp.vulnweb.com/artists.php?artist=1"
    logger.info(f"\nObteniendo baseline para: {test_url}")
    
    baseline = validator.get_baseline_response(test_url)
    
    if baseline:
        logger.info(f"✓ Baseline obtenido:")
        logger.info(f"  - Status: {baseline['status_code']}")
        logger.info(f"  - Longitud: {baseline['length']} bytes")
        logger.info(f"  - Hash: {baseline['hash']}")
        logger.info(f"  - Tiempo: {baseline['response_time']:.3f}s")
        
        # Simular respuesta con payload
        test_response = {
            'status_code': 200,
            'content': baseline['content'] + "\nSQL Error: syntax error",
            'length': baseline['length'] + 30,
            'hash': 'different_hash'
        }
        
        logger.info(f"\nComparando con respuesta de prueba...")
        comparison = validator.compare_responses(baseline, test_response)
        
        logger.info(f"\nResultados de comparación:")
        logger.info(f"  - Diferencia de status: {comparison['status_code_diff']}")
        logger.info(f"  - Diferencia de longitud: {comparison['length_diff']} bytes ({comparison['length_diff_percent']:.2f}%)")
        logger.info(f"  - Similitud de contenido: {comparison['similarity']:.2%}")
        logger.info(f"  - Diferencia significativa: {comparison['significant_diff']}")
        logger.info(f"  - Confianza: {comparison['confidence']}%")
    else:
        logger.error("No se pudo obtener baseline")
    
    logger.info("\n" + "=" * 80)

if __name__ == "__main__":
    # Ejecutar pruebas
    test_validation_system()
    test_baseline_comparison()
