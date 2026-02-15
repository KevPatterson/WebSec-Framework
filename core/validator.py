"""
Sistema de validación de vulnerabilidades.
Incluye comparación de respuestas baseline, detección de falsos positivos
y scoring de confianza.
"""
from core.logger import get_logger
import requests
import hashlib
import difflib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import re


class Validator:
    """
    Sistema de validación para reducir falsos positivos.
    
    Características:
    - Comparación de respuestas baseline
    - Detección de falsos positivos
    - Scoring de confianza (0-100)
    - Análisis de diferencias significativas
    - Validación de contexto
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger("validator")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Cache de baselines
        self.baseline_cache = {}
        
        # Umbrales de validación
        self.thresholds = {
            'min_confidence': 60,  # Confianza mínima para reportar
            'min_length_diff': 100,  # Diferencia mínima de longitud
            'min_similarity': 0.85,  # Similitud máxima para considerar diferente
            'max_response_time': 30,  # Timeout máximo
        }
    
    def validate(self, finding):
        """
        Valida un hallazgo para reducir falsos positivos.
        
        Args:
            finding (dict): Hallazgo a validar
            
        Returns:
            dict: Hallazgo validado con score de confianza
        """
        try:
            vuln_type = finding.get('vulnerability', '').lower()
            
            # Aplicar validación según tipo de vulnerabilidad
            if 'sqli' in vuln_type or 'sql injection' in vuln_type:
                return self._validate_sqli(finding)
            elif 'xss' in vuln_type:
                return self._validate_xss(finding)
            elif 'lfi' in vuln_type or 'rfi' in vuln_type:
                return self._validate_lfi(finding)
            elif 'csrf' in vuln_type:
                return self._validate_csrf(finding)
            elif 'cors' in vuln_type:
                return self._validate_cors(finding)
            else:
                # Validación genérica
                return self._validate_generic(finding)
        
        except Exception as e:
            self.logger.error(f"Error validando hallazgo: {e}")
            finding['confidence_score'] = 50  # Score neutral en caso de error
            finding['validation_status'] = 'error'
            return finding
    
    def get_baseline_response(self, url, method='GET', data=None, use_cache=True):
        """
        Obtiene respuesta baseline (sin payload malicioso).
        
        Args:
            url (str): URL a probar
            method (str): Método HTTP
            data (dict): Datos POST
            use_cache (bool): Usar cache de baselines
            
        Returns:
            dict: Respuesta baseline con metadata
        """
        cache_key = self._get_cache_key(url, method, data)
        
        # Verificar cache
        if use_cache and cache_key in self.baseline_cache:
            self.logger.debug(f"Usando baseline cacheado para {url}")
            return self.baseline_cache[cache_key]
        
        try:
            # Hacer request baseline
            if method.upper() == 'POST':
                response = self.session.post(url, data=data, timeout=10)
            else:
                response = self.session.get(url, timeout=10)
            
            baseline = {
                'status_code': response.status_code,
                'content': response.text,
                'length': len(response.text),
                'headers': dict(response.headers),
                'response_time': response.elapsed.total_seconds(),
                'hash': hashlib.md5(response.text.encode()).hexdigest()
            }
            
            # Cachear baseline
            if use_cache:
                self.baseline_cache[cache_key] = baseline
            
            return baseline
        
        except Exception as e:
            self.logger.error(f"Error obteniendo baseline: {e}")
            return None
    
    def compare_responses(self, baseline, test_response):
        """
        Compara respuesta baseline con respuesta de prueba.
        
        Args:
            baseline (dict): Respuesta baseline
            test_response (dict): Respuesta de prueba
            
        Returns:
            dict: Análisis de diferencias
        """
        if not baseline or not test_response:
            return {'significant_diff': False, 'confidence': 0}
        
        analysis = {
            'status_code_diff': baseline['status_code'] != test_response['status_code'],
            'length_diff': abs(baseline['length'] - test_response['length']),
            'length_diff_percent': 0,
            'hash_diff': baseline['hash'] != test_response['hash'],
            'similarity': 0,
            'significant_diff': False,
            'confidence': 0
        }
        
        # Calcular diferencia porcentual de longitud
        if baseline['length'] > 0:
            analysis['length_diff_percent'] = (analysis['length_diff'] / baseline['length']) * 100
        
        # Calcular similitud de contenido
        if baseline['content'] and test_response['content']:
            matcher = difflib.SequenceMatcher(None, baseline['content'], test_response['content'])
            analysis['similarity'] = matcher.ratio()
        
        # Determinar si hay diferencia significativa
        analysis['significant_diff'] = (
            analysis['status_code_diff'] or
            analysis['length_diff'] > self.thresholds['min_length_diff'] or
            analysis['similarity'] < self.thresholds['min_similarity']
        )
        
        # Calcular confianza basada en diferencias
        confidence = 0
        if analysis['status_code_diff']:
            confidence += 30
        if analysis['length_diff'] > self.thresholds['min_length_diff']:
            confidence += 25
        if analysis['similarity'] < self.thresholds['min_similarity']:
            confidence += 25
        if analysis['hash_diff']:
            confidence += 20
        
        analysis['confidence'] = min(confidence, 100)
        
        return analysis
    
    def _validate_sqli(self, finding):
        """Valida hallazgos de SQL Injection."""
        self.logger.debug(f"Validando SQLi: {finding.get('url')}")
        
        url = finding.get('url')
        payload = finding.get('payload', '')
        method = finding.get('method', 'GET')
        param = finding.get('parameter')
        
        confidence = 50  # Base
        
        # 1. Verificar evidencia de error SQL
        evidence = finding.get('details', {}).get('evidence', '')
        if evidence:
            # Buscar patrones de error SQL específicos
            sql_error_patterns = [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_',
                r'PostgreSQL.*ERROR',
                r'ORA-\d+',
                r'Microsoft SQL Server',
                r'SQLite.*error'
            ]
            
            for pattern in sql_error_patterns:
                if re.search(pattern, evidence, re.IGNORECASE):
                    confidence += 20
                    break
        
        # 2. Comparar con baseline
        try:
            baseline = self.get_baseline_response(url, method)
            
            if baseline:
                # Simular respuesta de prueba (en producción vendría del módulo)
                test_response = {
                    'status_code': finding.get('details', {}).get('status_code', 200),
                    'content': evidence,
                    'length': len(evidence),
                    'hash': hashlib.md5(evidence.encode()).hexdigest()
                }
                
                comparison = self.compare_responses(baseline, test_response)
                
                if comparison['significant_diff']:
                    confidence += 15
                
                finding['validation'] = {
                    'baseline_comparison': comparison,
                    'baseline_available': True
                }
        
        except Exception as e:
            self.logger.debug(f"Error en comparación baseline SQLi: {e}")
        
        # 3. Validar tipo de SQLi
        sqli_type = finding.get('details', {}).get('type', '')
        if sqli_type == 'error-based':
            confidence += 10  # Error-based es más confiable
        elif sqli_type == 'boolean-based':
            confidence += 5
        
        # 4. Verificar DBMS detectado
        if finding.get('details', {}).get('dbms'):
            confidence += 10
        
        finding['confidence_score'] = min(confidence, 100)
        finding['validation_status'] = 'validated' if confidence >= self.thresholds['min_confidence'] else 'low_confidence'
        
        return finding
    
    def _validate_xss(self, finding):
        """Valida hallazgos de XSS."""
        self.logger.debug(f"Validando XSS: {finding.get('url')}")
        
        confidence = 50  # Base
        
        # 1. Verificar contexto de inyección
        context = finding.get('details', {}).get('context', '')
        if context:
            # Contextos más peligrosos tienen mayor confianza
            dangerous_contexts = ['script', 'javascript', 'onerror', 'onload']
            if any(ctx in context.lower() for ctx in dangerous_contexts):
                confidence += 20
        
        # 2. Verificar payload reflejado
        payload = finding.get('payload', '')
        evidence = finding.get('details', {}).get('evidence', '')
        
        if payload and evidence:
            # Verificar si el payload está reflejado sin sanitización
            if payload in evidence:
                confidence += 25
            elif payload.replace('<', '&lt;').replace('>', '&gt;') in evidence:
                # Payload sanitizado = falso positivo
                confidence -= 30
                finding['validation_notes'] = 'Payload appears to be sanitized'
        
        # 3. Verificar tipo de XSS
        xss_type = finding.get('details', {}).get('type', '')
        if xss_type == 'reflected':
            confidence += 10
        elif xss_type == 'dom-based':
            confidence += 5  # DOM-based puede tener más falsos positivos
        
        # 4. Comparar con baseline
        try:
            url = finding.get('url')
            baseline = self.get_baseline_response(url)
            
            if baseline and payload not in baseline['content']:
                confidence += 10
        
        except Exception as e:
            self.logger.debug(f"Error en comparación baseline XSS: {e}")
        
        finding['confidence_score'] = min(max(confidence, 0), 100)
        finding['validation_status'] = 'validated' if confidence >= self.thresholds['min_confidence'] else 'low_confidence'
        
        return finding
    
    def _validate_lfi(self, finding):
        """Valida hallazgos de LFI/RFI."""
        self.logger.debug(f"Validando LFI: {finding.get('url')}")
        
        confidence = 50  # Base
        
        # 1. Verificar evidencia de archivo del sistema
        evidence = finding.get('details', {}).get('evidence', [])
        
        if evidence:
            # Signatures específicas de archivos del sistema
            linux_signatures = ['root:x:0:0:', 'daemon:', '/bin/bash', '/bin/sh']
            windows_signatures = ['[extensions]', '; for 16-bit app support', '[fonts]']
            
            for sig in linux_signatures + windows_signatures:
                if any(sig in str(ev) for ev in evidence):
                    confidence += 25
                    break
        
        # 2. Verificar payload usado
        payload = finding.get('payload', '')
        if payload:
            # Path traversal profundo es más confiable
            traversal_depth = payload.count('../') + payload.count('..\\')
            if traversal_depth >= 3:
                confidence += 10
            
            # Payloads absolutos son más confiables
            if payload.startswith('/etc/') or payload.startswith('C:\\'):
                confidence += 15
        
        # 3. Distinguir LFI vs RFI
        vuln_type = finding.get('vulnerability', '')
        if 'RFI' in vuln_type:
            # RFI es más crítico pero puede tener más falsos positivos
            confidence += 5
        else:
            confidence += 10  # LFI con evidencia es más confiable
        
        finding['confidence_score'] = min(confidence, 100)
        finding['validation_status'] = 'validated' if confidence >= self.thresholds['min_confidence'] else 'low_confidence'
        
        return finding
    
    def _validate_csrf(self, finding):
        """Valida hallazgos de CSRF."""
        self.logger.debug(f"Validando CSRF: {finding.get('url')}")
        
        confidence = 70  # Base alto (CSRF es más directo)
        
        vuln_subtype = finding.get('vulnerability', '')
        
        # 1. Missing Token es muy confiable
        if 'Missing Token' in vuln_subtype:
            confidence = 85
        
        # 2. Missing SameSite es confiable
        elif 'Missing SameSite' in vuln_subtype:
            confidence = 80
        
        # 3. Validación de Origin puede tener falsos positivos
        elif 'Origin' in vuln_subtype or 'Referer' in vuln_subtype:
            confidence = 65
        
        # 4. Endpoints desprotegidos necesitan más validación
        elif 'Unprotected Endpoint' in vuln_subtype:
            status_code = finding.get('details', {}).get('status_code', 0)
            if status_code in [200, 201, 204]:
                confidence = 70
            else:
                confidence = 50  # Puede ser falso positivo
        
        finding['confidence_score'] = confidence
        finding['validation_status'] = 'validated' if confidence >= self.thresholds['min_confidence'] else 'low_confidence'
        
        return finding
    
    def _validate_cors(self, finding):
        """Valida hallazgos de CORS."""
        self.logger.debug(f"Validando CORS: {finding.get('url')}")
        
        confidence = 75  # Base alto (CORS es verificable)
        
        vuln_subtype = finding.get('vulnerability', '')
        
        # 1. Wildcard con credentials es crítico y confiable
        if 'Credentials with Wildcard' in vuln_subtype or 'Origin Reflection with Credentials' in vuln_subtype:
            confidence = 95
        
        # 2. Wildcard simple es confiable
        elif 'Wildcard Origin' in vuln_subtype:
            confidence = 85
        
        # 3. Null origin es confiable
        elif 'Null Origin' in vuln_subtype:
            confidence = 80
        
        # 4. Métodos peligrosos necesitan contexto
        elif 'Dangerous Methods' in vuln_subtype:
            methods = finding.get('details', {}).get('dangerous_methods', [])
            if len(methods) >= 2:
                confidence = 75
            else:
                confidence = 65
        
        # 5. Reflexión arbitraria es confiable
        elif 'Arbitrary Origin Reflection' in vuln_subtype:
            confidence = 80
        
        finding['confidence_score'] = confidence
        finding['validation_status'] = 'validated' if confidence >= self.thresholds['min_confidence'] else 'low_confidence'
        
        return finding
    
    def _validate_generic(self, finding):
        """Validación genérica para otros tipos de vulnerabilidades."""
        self.logger.debug(f"Validando genérico: {finding.get('vulnerability')}")
        
        confidence = 60  # Base neutral
        
        # Ajustar según severidad
        severity = finding.get('severity', 'medium')
        if severity == 'critical':
            confidence += 10
        elif severity == 'high':
            confidence += 5
        
        # Ajustar según evidencia
        if finding.get('details', {}).get('evidence'):
            confidence += 10
        
        finding['confidence_score'] = confidence
        finding['validation_status'] = 'validated' if confidence >= self.thresholds['min_confidence'] else 'low_confidence'
        
        return finding
    
    def _get_cache_key(self, url, method, data):
        """Genera clave de cache para baseline."""
        key_parts = [url, method]
        if data:
            key_parts.append(str(sorted(data.items())))
        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()
    
    def validate_batch(self, findings):
        """
        Valida múltiples hallazgos en batch.
        
        Args:
            findings (list): Lista de hallazgos
            
        Returns:
            list: Hallazgos validados
        """
        validated = []
        
        for finding in findings:
            validated_finding = self.validate(finding)
            
            # Filtrar hallazgos de baja confianza si está configurado
            if self.config.get('filter_low_confidence', False):
                if validated_finding['confidence_score'] >= self.thresholds['min_confidence']:
                    validated.append(validated_finding)
            else:
                validated.append(validated_finding)
        
        self.logger.info(f"Validados {len(validated)}/{len(findings)} hallazgos")
        
        return validated
    
    def get_validation_stats(self, findings):
        """
        Obtiene estadísticas de validación.
        
        Args:
            findings (list): Lista de hallazgos validados
            
        Returns:
            dict: Estadísticas de validación
        """
        stats = {
            'total': len(findings),
            'validated': 0,
            'low_confidence': 0,
            'avg_confidence': 0,
            'by_confidence_range': {
                '90-100': 0,
                '70-89': 0,
                '60-69': 0,
                '0-59': 0
            }
        }
        
        total_confidence = 0
        
        for finding in findings:
            confidence = finding.get('confidence_score', 0)
            total_confidence += confidence
            
            if finding.get('validation_status') == 'validated':
                stats['validated'] += 1
            else:
                stats['low_confidence'] += 1
            
            # Clasificar por rango
            if confidence >= 90:
                stats['by_confidence_range']['90-100'] += 1
            elif confidence >= 70:
                stats['by_confidence_range']['70-89'] += 1
            elif confidence >= 60:
                stats['by_confidence_range']['60-69'] += 1
            else:
                stats['by_confidence_range']['0-59'] += 1
        
        if stats['total'] > 0:
            stats['avg_confidence'] = round(total_confidence / stats['total'], 2)
        
        return stats
