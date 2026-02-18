"""Validador específico para autenticación."""
from .base_validator import BaseValidator


class AuthValidator(BaseValidator):
    """Valida hallazgos de autenticación."""
    
    def validate(self, finding):
        """Valida hallazgo de autenticación."""
        confidence = 70  # Base alto
        
        vuln_subtype = finding.get('type', '')
        
        if 'default_credentials' in vuln_subtype:
            status_code = finding.get('details', {}).get('status_code', 0)
            confidence = 90 if status_code in [200, 302] else 50
        elif 'http_basic_auth' in vuln_subtype:
            confidence = 85 if finding.get('url', '').startswith('http://') else 60
        elif 'no_rate_limiting' in vuln_subtype:
            confidence = 65
        
        return self._set_confidence(finding, confidence)
