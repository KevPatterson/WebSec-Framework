"""Validador específico para SSRF."""
from .base_validator import BaseValidator


class SSRFValidator(BaseValidator):
    """Valida hallazgos de SSRF."""
    
    def validate(self, finding):
        """Valida hallazgo de SSRF."""
        confidence = 50  # Base medio
        
        # 1. Verificar evidencia de acceso interno
        evidence = finding.get('details', {}).get('evidence', '')
        if evidence:
            if 'latest/meta-data' in evidence or 'metadata.google.internal' in evidence:
                confidence += 40
            elif 'localhost' in evidence or '127.0.0.1' in evidence:
                confidence += 30
        
        # 2. Verificar diferencia de respuesta
        length_diff = finding.get('details', {}).get('length_diff', 0)
        if length_diff > 100:
            confidence += 15
        
        # 3. Verificar tipo de SSRF
        if 'metadata' in finding.get('title', '').lower():
            confidence += 10
        
        return self._set_confidence(finding, confidence)
