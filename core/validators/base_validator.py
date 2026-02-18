"""
Validador base con funcionalidad común.
"""
from abc import ABC, abstractmethod
from core.logger import get_logger


class BaseValidator(ABC):
    """
    Clase base para validadores específicos de vulnerabilidades.
    Implementa patrón estrategia para reducir acoplamiento.
    """
    
    def __init__(self, config, http_client=None):
        self.config = config
        self.logger = get_logger(f"{self.__class__.__name__.lower()}")
        self.http_client = http_client
        
        # Umbrales por defecto
        self.min_confidence = config.get('min_confidence', 60)
        self.min_length_diff = config.get('min_length_diff', 100)
        self.min_similarity = config.get('min_similarity', 0.85)
    
    @abstractmethod
    def validate(self, finding):
        """
        Valida un hallazgo específico.
        
        Args:
            finding: dict con información del hallazgo
            
        Returns:
            dict con hallazgo validado y confidence_score
        """
        pass
    
    def _set_confidence(self, finding, confidence, status='validated'):
        """
        Establece el score de confianza en un hallazgo.
        
        Args:
            finding: dict del hallazgo
            confidence: score de confianza (0-100)
            status: estado de validación
        """
        finding['confidence_score'] = min(max(confidence, 0), 100)
        finding['validation_status'] = status if confidence >= self.min_confidence else 'low_confidence'
        return finding
    
    def _compare_with_baseline(self, finding, baseline, test_response):
        """
        Compara respuesta de prueba con baseline.
        
        Args:
            finding: dict del hallazgo
            baseline: dict de respuesta baseline
            test_response: dict de respuesta de prueba
            
        Returns:
            int con puntos de confianza adicionales
        """
        if not baseline or not test_response:
            return 0
        
        confidence_boost = 0
        
        # Comparar status codes
        if baseline.get('status_code') != test_response.get('status_code'):
            confidence_boost += 15
        
        # Comparar longitud
        length_diff = abs(baseline.get('length', 0) - test_response.get('length', 0))
        if length_diff > self.min_length_diff:
            confidence_boost += 10
        
        # Comparar hash
        if baseline.get('hash') != test_response.get('hash'):
            confidence_boost += 5
        
        return confidence_boost
