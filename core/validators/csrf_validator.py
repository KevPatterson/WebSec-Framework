"""Validador específico para CSRF."""
from .base_validator import BaseValidator


class CSRFValidator(BaseValidator):
    """Valida hallazgos de CSRF."""
    
    def validate(self, finding):
        """Valida hallazgo de CSRF."""
        confidence = 70  # Base alto
        
        vuln_subtype = finding.get('type', '')
        status_code = finding.get('details', {}).get('status_code', 0)
        
        # Reducir confianza si endpoint no existe
        if status_code == 404:
            confidence = 40
            finding['validation_notes'] = 'Endpoint devuelve 404'
        elif 'Missing Token' in vuln_subtype:
            confidence = 85
        elif 'Missing SameSite' in vuln_subtype:
            confidence = 80
        elif 'Origin' in vuln_subtype or 'Referer' in vuln_subtype:
            confidence = 70 if status_code in [200, 201, 204] else 50
        elif 'Unprotected Endpoint' in vuln_subtype:
            confidence = 70 if status_code in [200, 201, 204] else 50
        
        return self._set_confidence(finding, confidence)
