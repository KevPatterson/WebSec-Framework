"""Validador específico para XXE."""
import re
from .base_validator import BaseValidator


class XXEValidator(BaseValidator):
    """Valida hallazgos de XXE con detección de falsos positivos."""
    
    HTML_ERROR_INDICATORS = [
        r'<!DOCTYPE html>',
        r'<html.*?>',
        r'404.*not found',
        r'page not found',
        r'__next',
        r'vercel',
    ]
    
    REAL_XXE_EVIDENCE = [
        r'root:.*:0:0:',
        r'/bin/bash',
        r'/bin/sh',
        r'daemon:.*:1:1:',
        r'\[fonts\]',
        r'for 16-bit app support',
    ]
    
    def validate(self, finding):
        """Valida hallazgo de XXE."""
        confidence = 30  # Base muy bajo
        
        evidence = finding.get('evidence', {}).get('evidence_found', '')
        response_snippet = finding.get('evidence', {}).get('response_snippet', '')
        
        # 1. Verificar que NO sea página de error HTML
        is_html_error = False
        for pattern in self.HTML_ERROR_INDICATORS:
            if re.search(pattern, response_snippet, re.IGNORECASE):
                is_html_error = True
                confidence = 10
                finding['validation_notes'] = 'Página de error HTML genérica'
                break
        
        # 2. Buscar evidencia REAL de XXE
        has_real_evidence = False
        for pattern in self.REAL_XXE_EVIDENCE:
            if re.search(pattern, response_snippet):
                confidence += 60
                has_real_evidence = True
                finding['validation_notes'] = 'Evidencia real de XXE'
                break
        
        # 3. Verificar status code
        status_code = finding.get('evidence', {}).get('status_code')
        if status_code == 404:
            confidence = 5
            finding['validation_notes'] = 'Endpoint no existe (404)'
        elif status_code and status_code >= 400:
            confidence -= 20
        
        # 4. Verificar longitud de respuesta
        if len(response_snippet) > 1000 and not has_real_evidence:
            confidence -= 15
        
        # 5. Si solo detectó "<html" es falso positivo
        if evidence == '<html' and is_html_error:
            confidence = 5
            finding['validation_notes'] = 'Solo tag HTML - falso positivo'
        
        return self._set_confidence(finding, confidence)
