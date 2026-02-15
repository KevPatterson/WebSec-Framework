# Sistema de Validación de Vulnerabilidades

## Descripción General

El sistema de validación implementa técnicas avanzadas para reducir falsos positivos y proporcionar scoring de confianza en los hallazgos de seguridad.

---

## 🎯 Características Principales

### 1. Comparación de Respuestas Baseline
- Captura respuestas "limpias" sin payloads maliciosos
- Cache inteligente de baselines para optimizar performance
- Análisis de diferencias significativas

### 2. Detección de Falsos Positivos
- Validación específica por tipo de vulnerabilidad
- Análisis de evidencia y contexto
- Verificación de sanitización de inputs

### 3. Scoring de Confianza (0-100)
- Algoritmo multi-factor para calcular confianza
- Clasificación automática: Muy Alta, Alta, Media, Baja
- Filtrado opcional de hallazgos de baja confianza

### 4. Análisis de Diferencias
- Comparación de status codes
- Análisis de longitud de respuesta
- Cálculo de similitud de contenido (difflib)
- Detección de cambios significativos

---

## 📊 Scoring de Confianza

### Rangos de Confianza

| Rango | Clasificación | Descripción | Acción Recomendada |
|-------|---------------|-------------|-------------------|
| 90-100% | 🟢 Muy Alta | Evidencia sólida, muy probable | Reportar inmediatamente |
| 70-89% | 🟡 Alta | Evidencia clara, probable | Reportar con prioridad |
| 60-69% | 🟠 Media | Evidencia moderada, posible | Verificar manualmente |
| 0-59% | 🔴 Baja | Evidencia débil, dudoso | Requiere validación manual |

### Factores de Scoring

#### SQLi (SQL Injection)
```
Base: 50 puntos
+ 20 puntos: Error SQL específico detectado
+ 15 puntos: Diferencia significativa vs baseline
+ 10 puntos: Error-based (más confiable que boolean-based)
+ 10 puntos: DBMS identificado
+ 5 puntos: Boolean-based
```

#### XSS (Cross-Site Scripting)
```
Base: 50 puntos
+ 25 puntos: Payload reflejado sin sanitización
+ 20 puntos: Contexto peligroso (script, onerror, onload)
+ 10 puntos: Reflected XSS
+ 10 puntos: Payload no presente en baseline
+ 5 puntos: DOM-based XSS
- 30 puntos: Payload sanitizado (falso positivo)
```

#### LFI/RFI (File Inclusion)
```
Base: 50 puntos
+ 25 puntos: Signature de archivo del sistema detectada
+ 15 puntos: Path absoluto usado
+ 10 puntos: Path traversal profundo (>= 3 niveles)
+ 10 puntos: LFI con evidencia
+ 5 puntos: RFI detectado
```

#### CSRF (Cross-Site Request Forgery)
```
Base: 70 puntos (más directo)
Missing Token: 85 puntos
Missing SameSite: 80 puntos
Origin/Referer validation: 65 puntos
Unprotected Endpoint: 50-70 puntos (según status code)
```

#### CORS (Misconfiguration)
```
Base: 75 puntos (verificable)
Credentials + Wildcard/Reflection: 95 puntos (crítico)
Wildcard Origin: 85 puntos
Null Origin: 80 puntos
Arbitrary Reflection: 80 puntos
Dangerous Methods: 65-75 puntos (según cantidad)
```

---

## 🔧 Uso del Sistema

### Integración Automática con Scanner

```python
from core.scanner import Scanner
from modules.sqli import SQLiModule

# Configuración con validación habilitada (por defecto)
config = {
    "target_url": "https://example.com",
    "enable_validation": True,  # Habilitar validación
    "filter_low_confidence": False  # Mostrar todos los hallazgos
}

scanner = Scanner("https://example.com", config)
scanner.register_module(SQLiModule(config))
scanner.run()

# Los hallazgos se validan automáticamente
# Cada hallazgo incluye:
# - confidence_score: 0-100
# - validation_status: 'validated' o 'low_confidence'
```

### Uso Directo del Validador

```python
from core.validator import Validator

config = {"target_url": "https://example.com"}
validator = Validator(config)

# Validar un hallazgo individual
finding = {
    "vulnerability": "SQLi - Error-based",
    "url": "https://example.com/page?id=1'",
    "details": {
        "evidence": "SQL syntax error"
    }
}

validated = validator.validate(finding)
print(f"Confianza: {validated['confidence_score']}%")
print(f"Estado: {validated['validation_status']}")

# Validar múltiples hallazgos
findings = [finding1, finding2, finding3]
validated_findings = validator.validate_batch(findings)

# Obtener estadísticas
stats = validator.get_validation_stats(validated_findings)
print(f"Confianza promedio: {stats['avg_confidence']}%")
```

### Comparación de Baseline

```python
# Obtener respuesta baseline
baseline = validator.get_baseline_response(
    url="https://example.com/page?id=1",
    method="GET",
    use_cache=True
)

# Simular respuesta con payload
test_response = {
    'status_code': 200,
    'content': "Response with SQL error",
    'length': 1500,
    'hash': 'abc123'
}

# Comparar respuestas
comparison = validator.compare_responses(baseline, test_response)

if comparison['significant_diff']:
    print(f"Diferencia detectada!")
    print(f"Confianza: {comparison['confidence']}%")
    print(f"Similitud: {comparison['similarity']:.2%}")
```

---

## 📈 Estadísticas de Validación

El sistema proporciona estadísticas detalladas:

```python
stats = validator.get_validation_stats(findings)

# Estructura de estadísticas:
{
    'total': 10,
    'validated': 7,
    'low_confidence': 3,
    'avg_confidence': 72.5,
    'by_confidence_range': {
        '90-100': 2,  # Muy alta
        '70-89': 5,   # Alta
        '60-69': 1,   # Media
        '0-59': 2     # Baja
    }
}
```

### Visualización en Scanner

El scanner muestra automáticamente las estadísticas:

```
============================================================
ESTADÍSTICAS DE VALIDACIÓN
============================================================
Total de hallazgos: 10
Validados (confianza >= 60): 8
Baja confianza (< 60): 2
Confianza promedio: 72.5%

Distribución por confianza:
  90-100% (Muy alta): 2
  70-89%  (Alta):     5
  60-69%  (Media):    1
  0-59%   (Baja):     2
============================================================
```

---

## 🧪 Pruebas y Validación

### Script de Prueba

```bash
# Ejecutar pruebas del sistema de validación
python test_validation_system.py

# Resultados en:
# - reports/validation_test_results.json
```

### Casos de Prueba Incluidos

1. **SQLi con evidencia fuerte** → Confianza: 95%
2. **SQLi sin evidencia** → Confianza: 55% (baja)
3. **XSS sanitizado** → Confianza: 45% (falso positivo)
4. **XSS sin sanitizar** → Confianza: 95%
5. **LFI con /etc/passwd** → Confianza: 85%
6. **CSRF Missing Token** → Confianza: 85%
7. **CORS con credentials** → Confianza: 95%

---

## 🔍 Técnicas de Validación

### 1. Análisis de Evidencia

**SQLi:**
- Busca patrones de error SQL específicos
- Identifica DBMS (MySQL, PostgreSQL, MSSQL, Oracle)
- Valida tipo de SQLi (error-based vs boolean-based)

**XSS:**
- Verifica si el payload está reflejado
- Detecta sanitización HTML
- Analiza contexto de inyección

**LFI:**
- Busca signatures de archivos del sistema
- Valida profundidad de path traversal
- Distingue entre LFI y RFI

### 2. Comparación Baseline

```python
# Proceso de comparación:
1. Obtener respuesta baseline (sin payload)
2. Obtener respuesta con payload
3. Comparar:
   - Status codes
   - Longitud de respuesta
   - Contenido (similitud)
   - Hash MD5
4. Calcular diferencias significativas
5. Ajustar score de confianza
```

### 3. Validación de Contexto

- **CSRF:** Verifica presencia de tokens, SameSite, Origin
- **CORS:** Valida headers ACAO, ACAC, métodos permitidos
- **Headers:** Verifica configuraciones según estándares

---

## ⚙️ Configuración Avanzada

### Umbrales Personalizados

```python
validator = Validator(config)

# Modificar umbrales
validator.thresholds = {
    'min_confidence': 70,      # Confianza mínima (default: 60)
    'min_length_diff': 150,    # Diferencia mínima de longitud (default: 100)
    'min_similarity': 0.90,    # Similitud máxima (default: 0.85)
    'max_response_time': 20    # Timeout (default: 30)
}
```

### Filtrado de Baja Confianza

```python
config = {
    "enable_validation": True,
    "filter_low_confidence": True  # Filtrar hallazgos < 60%
}

scanner = Scanner(target_url, config)
scanner.run()

# Solo se reportan hallazgos con confianza >= 60%
```

### Cache de Baselines

```python
# Habilitar cache (default: True)
baseline = validator.get_baseline_response(url, use_cache=True)

# Limpiar cache
validator.baseline_cache.clear()

# Ver cache
print(f"Baselines cacheados: {len(validator.baseline_cache)}")
```

---

## 📊 Formato de Salida

### Hallazgo Validado

```json
{
  "vulnerability": "SQLi - Error-based",
  "severity": "critical",
  "cvss_score": 9.8,
  "url": "https://example.com/page?id=1'",
  "confidence_score": 95,
  "validation_status": "validated",
  "validation": {
    "baseline_comparison": {
      "status_code_diff": false,
      "length_diff": 250,
      "length_diff_percent": 15.5,
      "similarity": 0.75,
      "significant_diff": true,
      "confidence": 70
    },
    "baseline_available": true
  },
  "details": {
    "evidence": "SQL syntax error",
    "dbms": "MySQL"
  }
}
```

### Reporte Consolidado

```json
{
  "scan_info": {
    "validation_enabled": true
  },
  "validation_stats": {
    "total": 10,
    "validated": 8,
    "low_confidence": 2,
    "avg_confidence": 75.5,
    "by_confidence_range": {
      "90-100": 3,
      "70-89": 5,
      "60-69": 0,
      "0-59": 2
    }
  },
  "findings_by_confidence": {
    "high": [...],      // 90-100%
    "medium": [...],    // 70-89%
    "low": [...],       // 60-69%
    "very_low": [...]   // 0-59%
  }
}
```

---

## 🎓 Mejores Prácticas

### 1. Siempre Habilitar Validación
```python
config = {"enable_validation": True}  # Recomendado
```

### 2. Revisar Hallazgos de Baja Confianza
- No descartar automáticamente
- Validar manualmente los más críticos
- Ajustar umbrales según necesidad

### 3. Usar Cache de Baselines
- Mejora performance significativamente
- Especialmente útil en escaneos grandes
- Limpiar cache entre escaneos diferentes

### 4. Analizar Estadísticas
- Confianza promedio indica calidad del escaneo
- Alta proporción de baja confianza → revisar configuración
- Ajustar umbrales según resultados

### 5. Combinar con Validación Manual
- Sistema automatizado no es 100% perfecto
- Validar manualmente hallazgos críticos
- Usar scoring como guía, no verdad absoluta

---

## 🔬 Algoritmos Implementados

### Cálculo de Similitud
```python
# Usa difflib.SequenceMatcher
matcher = difflib.SequenceMatcher(None, baseline, test)
similarity = matcher.ratio()  # 0.0 - 1.0
```

### Detección de Diferencias Significativas
```python
significant = (
    status_code_diff OR
    length_diff > threshold OR
    similarity < threshold
)
```

### Scoring Multi-Factor
```python
confidence = base_score
+ evidence_score
+ baseline_comparison_score
+ context_score
+ type_specific_score

confidence = min(confidence, 100)  # Cap at 100
```

---

## 📚 Referencias

- **OWASP Testing Guide**: Validation techniques
- **CVSS Scoring**: Confidence metrics
- **Burp Suite**: False positive detection
- **Acunetix**: Validation algorithms

---

## 🚀 Roadmap

### Futuras Mejoras
- [ ] Machine Learning para scoring
- [ ] Validación con múltiples payloads
- [ ] Análisis de timing para blind SQLi
- [ ] Integración con WAF detection
- [ ] Validación colaborativa (crowd-sourced)
- [ ] Exportación de métricas de validación
- [ ] Dashboard de confianza en tiempo real

---

**Desarrollado con ❤️ para reducir falsos positivos y mejorar la precisión**
