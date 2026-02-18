"""Validador específico para SQL Injection."""
import re
from .base_validator import BaseValidator


class SQLiValidator(BaseValidator):
    """Valida hallazgos de SQL Injection."""
    
    SQL_ERROR_PATTERNS = [
        r'SQL syntax.*MySQL',
        r'Warning.*mysql_',
        r'PostgreSQL.*ERROR',
        r'ORA-\d+',
        r'Microsoft SQL Server',
        r'SQLite.*error'
    ]
    
    def validate(self, finding):
        """Valida hallazgo de SQLi."""
        confidence = 50  # Base
        
        # 1. Verificar evidencia de error SQL
        evidence = finding.get('details', {}).get('evidence', '')
        if evidence:
            for pattern in self.SQL_ERROR_PATTERNS:
                if re.search(pattern, evidence, re.IGNORECASE):
                    confidence += 20
                    break
        
        # 2. Validar tipo de SQLi
        sqli_type = finding.get('details', {}).get('type', '')
        if sqli_type == 'error-based':
            confidence += 10
        elif sqli_type == 'boolean-based':
            confidence += 5
        
        # 3. Verificar DBMS detectado
        if finding.get('details', {}).get('dbms'):
            confidence += 10
        
        # 4. Comparar con baseline si está disponible
        if self.http_client:
            try:
                url = finding.get('url')
                baseline = self.http_client.get_baseline_response(url)
                test_response = {
                    'status_code': finding.get('details', {}).get('status_code', 200),
                    'content': evidence,
                    'length': len(evidence),
                    'hash': None
                }
                confidence += self._compare_with_baseline(finding, baseline, test_response)
            except Exception:
                pass
        
        return self._set_confidence(finding, confidence)
