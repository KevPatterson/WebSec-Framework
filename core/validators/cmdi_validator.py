"""Validador específico para Command Injection."""
from .base_validator import BaseValidator


class CMDIValidator(BaseValidator):
    """Valida hallazgos de Command Injection."""
    
    def validate(self, finding):
        """Valida hallazgo de CMDI."""
        confidence = 50  # Base medio
        
        # 1. Verificar evidencia de ejecución
        evidence = finding.get('details', {}).get('evidence', [])
        if evidence:
            strong_patterns = ['uid=', 'gid=', 'root', 'Directory of']
            if any(pattern in str(evidence) for pattern in strong_patterns):
                confidence += 35
            else:
                confidence += 15
        
        # 2. Verificar tipo de detección
        detection_type = finding.get('details', {}).get('type', '')
        if detection_type == 'output-based':
            confidence += 10
        elif detection_type == 'time-based':
            confidence += 5
        
        # 3. Verificar payload
        payload = finding.get('payload', '')
        if payload and ('sleep' in payload or 'timeout' in payload):
            confidence -= 10  # Time-based menos confiable
        
        return self._set_confidence(finding, confidence)
