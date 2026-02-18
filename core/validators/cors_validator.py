"""Validador específico para CORS."""
from .base_validator import BaseValidator


class CORSValidator(BaseValidator):
    """Valida hallazgos de CORS."""
    
    def validate(self, finding):
        """Valida hallazgo de CORS."""
        confidence = 75  # Base alto
        
        vuln_subtype = finding.get('vulnerability', '')
        
        if 'Credentials with Wildcard' in vuln_subtype or 'Origin Reflection with Credentials' in vuln_subtype:
            confidence = 95
        elif 'Wildcard Origin' in vuln_subtype:
            confidence = 85
        elif 'Null Origin' in vuln_subtype:
            confidence = 80
        elif 'Dangerous Methods' in vuln_subtype:
            methods = finding.get('details', {}).get('dangerous_methods', [])
            confidence = 75 if len(methods) >= 2 else 65
        elif 'Arbitrary Origin Reflection' in vuln_subtype:
            confidence = 80
        
        return self._set_confidence(finding, confidence)
