"""Validador específico para XSS."""
from .base_validator import BaseValidator


class XSSValidator(BaseValidator):
    """Valida hallazgos de XSS."""
    
    def validate(self, finding):
        """Valida hallazgo de XSS."""
        confidence = 50  # Base
        
        # 1. Verificar contexto de inyección
        context = finding.get('details', {}).get('context', '')
        if context:
            dangerous_contexts = ['script', 'javascript', 'onerror', 'onload']
            if any(ctx in context.lower() for ctx in dangerous_contexts):
                confidence += 20
        
        # 2. Verificar payload reflejado
        payload = finding.get('payload', '')
        evidence = finding.get('details', {}).get('evidence', '')
        
        if payload and evidence:
            if payload in evidence:
                confidence += 25
            elif payload.replace('<', '&lt;').replace('>', '&gt;') in evidence:
                confidence -= 30
                finding['validation_notes'] = 'Payload sanitizado'
        
        # 3. Verificar tipo de XSS
        xss_type = finding.get('details', {}).get('type', '')
        if xss_type == 'reflected':
            confidence += 10
        elif xss_type == 'dom-based':
            confidence += 5
        
        # 4. Comparar con baseline
        if self.http_client:
            try:
                url = finding.get('url')
                baseline = self.http_client.get_baseline_response(url)
                if baseline and payload not in baseline['content']:
                    confidence += 10
            except Exception:
                pass
        
        return self._set_confidence(finding, confidence)
