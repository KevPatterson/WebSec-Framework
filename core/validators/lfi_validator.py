"""Validador específico para LFI/RFI."""
from .base_validator import BaseValidator


class LFIValidator(BaseValidator):
    """Valida hallazgos de LFI/RFI."""
    
    LINUX_SIGNATURES = ['root:x:0:0:', 'daemon:', '/bin/bash', '/bin/sh']
    WINDOWS_SIGNATURES = ['[extensions]', '; for 16-bit app support', '[fonts]']
    
    def validate(self, finding):
        """Valida hallazgo de LFI."""
        confidence = 50  # Base
        
        # 1. Verificar evidencia de archivo del sistema
        evidence = finding.get('details', {}).get('evidence', [])
        
        if evidence:
            for sig in self.LINUX_SIGNATURES + self.WINDOWS_SIGNATURES:
                if any(sig in str(ev) for ev in evidence):
                    confidence += 25
                    break
        
        # 2. Verificar payload usado
        payload = finding.get('payload', '')
        if payload:
            traversal_depth = payload.count('../') + payload.count('..\\')
            if traversal_depth >= 3:
                confidence += 10
            
            if payload.startswith('/etc/') or payload.startswith('C:\\'):
                confidence += 15
        
        # 3. Distinguir LFI vs RFI
        vuln_type = finding.get('vulnerability', '')
        if 'RFI' in vuln_type:
            confidence += 5
        else:
            confidence += 10
        
        return self._set_confidence(finding, confidence)
