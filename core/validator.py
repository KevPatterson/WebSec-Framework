"""
Sistema de validación de vulnerabilidades refactorizado.
Usa patrón estrategia para reducir acoplamiento.
"""
from core.logger import get_logger
from core.http_client import HTTPClient
from core.validators import (
    SQLiValidator, XSSValidator, LFIValidator, CSRFValidator,
    CORSValidator, XXEValidator, SSRFValidator, CMDIValidator, AuthValidator
)


class Validator:
    """
    Sistema de validación refactorizado con patrón estrategia.
    Delega validación específica a validadores especializados.
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger("validator")
        
        # Cliente HTTP compartido
        self.http_client = HTTPClient(config)
        
        # Umbrales de validación
        self.thresholds = {
            'min_confidence': config.get('min_confidence', 60),
            'min_length_diff': config.get('min_length_diff', 100),
            'min_similarity': config.get('min_similarity', 0.85),
        }
        
        # Inicializar validadores específicos
        self.validators = {
            'sqli': SQLiValidator(config, self.http_client),
            'sql injection': SQLiValidator(config, self.http_client),
            'xss': XSSValidator(config, self.http_client),
            'lfi': LFIValidator(config, self.http_client),
            'rfi': LFIValidator(config, self.http_client),
            'csrf': CSRFValidator(config, self.http_client),
            'cors': CORSValidator(config, self.http_client),
            'xxe': XXEValidator(config, self.http_client),
            'ssrf': SSRFValidator(config, self.http_client),
            'cmdi': CMDIValidator(config, self.http_client),
            'command': CMDIValidator(config, self.http_client),
            'auth': AuthValidator(config, self.http_client),
        }
    
    def validate(self, finding):
        """
        Valida un hallazgo usando el validador específico apropiado.
        
        Args:
            finding (dict): Hallazgo a validar
            
        Returns:
            dict: Hallazgo validado con score de confianza
        """
        try:
            vuln_type = finding.get('type', finding.get('vulnerability', '')).lower()
            
            # Buscar validador específico
            validator = None
            for key, val in self.validators.items():
                if key in vuln_type:
                    validator = val
                    break
            
            # Usar validador específico o genérico
            if validator:
                return validator.validate(finding)
            else:
                return self._validate_generic(finding)
        
        except Exception as e:
            self.logger.error(f"Error validando hallazgo: {e}")
            finding['confidence_score'] = 50
            finding['validation_status'] = 'error'
            return finding
    
    def get_baseline_response(self, url, method='GET', data=None, use_cache=True):
        """Wrapper para compatibilidad con código existente."""
        return self.http_client.get_baseline_response(url, method, data, use_cache)
    
    def compare_responses(self, baseline, test_response):
        """Wrapper para compatibilidad con código existente."""
        return self.http_client.compare_responses(baseline, test_response)
    

    
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
