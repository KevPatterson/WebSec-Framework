"""
Módulo de detección de SQL Injection.
Incluye detección básica y orquestación con SQLMap para explotación avanzada.
"""

import requests
import re
import time
import subprocess
import json
import os
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from core.base_module import VulnerabilityModule
from core.logger import get_logger
from datetime import datetime


class SQLiModule(VulnerabilityModule):
    """
    Detecta vulnerabilidades SQL Injection.
    Soporta detección básica y orquestación con SQLMap.
    """
    
    # Payloads de prueba básicos
    BASIC_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ]
    
    # Patrones de error SQL comunes
    SQL_ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        
        # PostgreSQL
        r"PostgreSQL.*?ERROR",
        r"Warning.*?pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        
        # MSSQL
        r"Driver.*? SQL[\-\_\ ]*Server",
        r"OLE DB.*? SQL Server",
        r"(\W|\A)SQL Server.*?Driver",
        r"Warning.*?mssql_.*",
        r"Microsoft SQL Native Client error",
        
        # Oracle
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?oci_.*",
        
        # SQLite
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        
        # Generic
        r"syntax error",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
    ]
    
    # Patrones de respuesta para Boolean-based
    BOOLEAN_PATTERNS = {
        'true_indicators': [
            r'welcome',
            r'success',
            r'logged in',
            r'valid',
        ],
        'false_indicators': [
            r'error',
            r'invalid',
            r'incorrect',
            r'failed',
        ]
    }

    def __init__(self, config):
        super().__init__(config)
        self.logger = get_logger("sqli_module")
        self.target_url = config.get("target_url")
        self.findings = []
        self.tested_params = set()
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")
        
        # Cargar payloads desde archivo
        self.payloads = self._load_payloads()
        
        # Configuración
        self.timeout = config.get("timeout", 10)
        self.max_payloads = config.get("max_sqli_payloads", 15)
        self.use_sqlmap = config.get("use_sqlmap", False)  # Deshabilitado por defecto
        
        # SQLMap runner
        self.sqlmap_runner = None
        if self.use_sqlmap:
            try:
                from core.external.sqlmap_runner import SqlmapRunner
                self.sqlmap_runner = SqlmapRunner(config)
            except Exception as e:
                self.logger.warning(f"[SQLi] No se pudo inicializar SQLMap: {e}")

    def _load_payloads(self):
        """Carga payloads desde archivo."""
        payloads = []
        payload_file = "payloads/sqli.txt"
        
        try:
            if os.path.exists(payload_file):
                with open(payload_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            payloads.append(line)
                self.logger.info(f"[SQLi] Cargados {len(payloads)} payloads desde {payload_file}")
            else:
                self.logger.warning(f"[SQLi] Archivo de payloads no encontrado: {payload_file}")
                payloads = self.BASIC_PAYLOADS
        except Exception as e:
            self.logger.error(f"[SQLi] Error cargando payloads: {e}")
            payloads = self.BASIC_PAYLOADS
        
        return payloads[:self.max_payloads]

    def scan(self):
        """Ejecuta el escaneo completo de SQLi."""
        self.logger.info(f"[SQLi] Iniciando escaneo de SQL Injection en: {self.target_url}")
        
        try:
            # 1. Detectar puntos de inyección
            injection_points = self._discover_injection_points()
            
            if not injection_points:
                self.logger.warning("[SQLi] No se encontraron puntos de inyección")
                return
            
            self.logger.info(f"[SQLi] Encontrados {len(injection_points)} puntos de inyección")
            
            # 2. Prueba básica de SQLi (Error-based y Boolean-based)
            self._test_error_based_sqli(injection_points)
            self._test_boolean_based_sqli(injection_points)
            
            # 3. Si se encontraron vulnerabilidades y SQLMap está habilitado, ejecutarlo
            if self.findings and self.use_sqlmap and self.sqlmap_runner:
                self._run_sqlmap_on_findings()
            
            # 4. Exportar resultados
            self._export_results()
            
            # Resumen
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            
            self.logger.info(f"[SQLi] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[SQLi] Severidad: Critical={critical}, High={high}")
            
        except Exception as e:
            self.logger.error(f"[SQLi] Error inesperado: {e}")

    def _discover_injection_points(self):
        """Descubre puntos de inyección (parámetros GET, formularios)."""
        injection_points = []
        
        try:
            response = requests.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Parámetros GET
            parsed = urlparse(self.target_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    injection_points.append({
                        'type': 'GET',
                        'url': self.target_url,
                        'param': param,
                        'method': 'GET'
                    })
            
            # 2. Formularios HTML
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                action_url = urljoin(self.target_url, action) if action else self.target_url
                
                inputs = form.find_all(['input', 'textarea'])
                for inp in inputs:
                    name = inp.get('name')
                    inp_type = inp.get('type', 'text').lower()
                    
                    # Priorizar campos que probablemente interactúen con BD
                    if name and inp_type not in ['submit', 'button', 'reset', 'file']:
                        injection_points.append({
                            'type': 'FORM',
                            'url': action_url,
                            'param': name,
                            'method': method,
                            'input_type': inp_type
                        })
            
            self.logger.info(f"[SQLi] Descubiertos {len(injection_points)} puntos de inyección")
            
        except Exception as e:
            self.logger.error(f"[SQLi] Error descubriendo puntos de inyección: {e}")
        
        return injection_points

    def _test_error_based_sqli(self, injection_points):
        """Prueba Error-based SQL Injection."""
        self.logger.info("[SQLi] Probando Error-based SQLi...")
        
        error_payloads = ["'", "\"", "' OR '1'='1", "1' AND '1'='2"]
        
        for point in injection_points:
            param_key = f"{point['url']}:{point['param']}"
            if param_key in self.tested_params:
                continue
            
            self.tested_params.add(param_key)
            
            # Obtener respuesta baseline
            try:
                baseline_response = self._make_request(point, "normal_value")
                baseline_text = baseline_response.text if baseline_response else ""
            except:
                continue
            
            for payload in error_payloads:
                try:
                    response = self._make_request(point, payload)
                    
                    if not response:
                        continue
                    
                    # Buscar errores SQL
                    sql_error = self._detect_sql_error(response.text)
                    
                    if sql_error:
                        finding = {
                            "type": "error_based_sqli",
                            "severity": "critical",
                            "title": f"SQL Injection (Error-based) en parámetro '{point['param']}'",
                            "description": f"El parámetro '{point['param']}' es vulnerable a SQL Injection. Se detectaron mensajes de error SQL en la respuesta.",
                            "cvss": 9.8,
                            "cwe": "CWE-89",
                            "owasp": "A03:2021 - Injection",
                            "recommendation": "Usar consultas parametrizadas (prepared statements) o un ORM. Nunca concatenar entrada del usuario directamente en queries SQL.",
                            "references": [
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                            ],
                            "evidence": {
                                "url": point['url'],
                                "parameter": point['param'],
                                "method": point['method'],
                                "payload": payload,
                                "sql_error": sql_error,
                                "vulnerable": True
                            }
                        }
                        
                        self.findings.append(finding)
                        self.logger.warning(f"[SQLi] Error-based SQLi encontrado: {point['url']} (param: {point['param']})")
                        break
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.debug(f"[SQLi] Error probando {point['param']}: {e}")

    def _test_boolean_based_sqli(self, injection_points):
        """Prueba Boolean-based SQL Injection."""
        self.logger.info("[SQLi] Probando Boolean-based SQLi...")
        
        for point in injection_points:
            param_key = f"{point['url']}:{point['param']}:boolean"
            if param_key in self.tested_params:
                continue
            
            self.tested_params.add(param_key)
            
            try:
                # Obtener respuesta baseline
                baseline_response = self._make_request(point, "1")
                if not baseline_response:
                    continue
                
                baseline_len = len(baseline_response.text)
                
                # Probar condición TRUE
                true_payload = "1' AND '1'='1"
                true_response = self._make_request(point, true_payload)
                
                # Probar condición FALSE
                false_payload = "1' AND '1'='2"
                false_response = self._make_request(point, false_payload)
                
                if not true_response or not false_response:
                    continue
                
                true_len = len(true_response.text)
                false_len = len(false_response.text)
                
                # Si las respuestas difieren significativamente, posible SQLi
                if abs(true_len - baseline_len) < 100 and abs(false_len - baseline_len) > 100:
                    finding = {
                        "type": "boolean_based_sqli",
                        "severity": "high",
                        "title": f"SQL Injection (Boolean-based) en parámetro '{point['param']}'",
                        "description": f"El parámetro '{point['param']}' es vulnerable a Boolean-based SQL Injection. Las respuestas varían según la condición SQL.",
                        "cvss": 8.6,
                        "cwe": "CWE-89",
                        "owasp": "A03:2021 - Injection",
                        "recommendation": "Usar consultas parametrizadas (prepared statements). Implementar validación de entrada estricta.",
                        "references": [
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                            "https://portswigger.net/web-security/sql-injection/blind"
                        ],
                        "evidence": {
                            "url": point['url'],
                            "parameter": point['param'],
                            "method": point['method'],
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "baseline_length": baseline_len,
                            "true_length": true_len,
                            "false_length": false_len,
                            "vulnerable": True
                        }
                    }
                    
                    self.findings.append(finding)
                    self.logger.warning(f"[SQLi] Boolean-based SQLi encontrado: {point['url']} (param: {point['param']})")
                
                time.sleep(0.2)
                
            except Exception as e:
                self.logger.debug(f"[SQLi] Error probando boolean-based en {point['param']}: {e}")

    def _make_request(self, point, payload):
        """Realiza una petición HTTP con el payload."""
        try:
            if point['method'] == 'GET':
                parsed = urlparse(point['url'])
                params = parse_qs(parsed.query)
                params[point['param']] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                return requests.get(test_url, timeout=self.timeout, allow_redirects=True)
            
            else:  # POST
                data = {point['param']: payload}
                return requests.post(point['url'], data=data, timeout=self.timeout, allow_redirects=True)
        
        except Exception as e:
            self.logger.debug(f"[SQLi] Error en request: {e}")
            return None

    def _detect_sql_error(self, response_text):
        """Detecta mensajes de error SQL en la respuesta."""
        for pattern in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _run_sqlmap_on_findings(self):
        """Ejecuta SQLMap en los hallazgos encontrados para explotación avanzada."""
        self.logger.info("[SQLi] Ejecutando SQLMap en hallazgos...")
        
        for finding in self.findings:
            if finding.get('evidence', {}).get('vulnerable'):
                url = finding['evidence']['url']
                param = finding['evidence']['parameter']
                
                self.logger.info(f"[SQLi] Ejecutando SQLMap en {url} (param: {param})")
                
                try:
                    sqlmap_results = self.sqlmap_runner.run(
                        target=url,
                        data=None,
                        extra_args=[f"-p {param}", "--batch", "--level=1", "--risk=1"]
                    )
                    
                    if sqlmap_results:
                        finding['sqlmap_results'] = sqlmap_results
                        self.logger.info(f"[SQLi] SQLMap completado para {param}")
                
                except Exception as e:
                    self.logger.error(f"[SQLi] Error ejecutando SQLMap: {e}")

    def _export_results(self):
        """Exporta los hallazgos a JSON."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            output_data = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": self.scan_timestamp,
                    "module": "sqli",
                    "total_findings": len(self.findings),
                    "tested_parameters": len(self.tested_params),
                    "sqlmap_used": self.use_sqlmap
                },
                "findings": self.findings,
                "summary": {
                    "critical": len([f for f in self.findings if f["severity"] == "critical"]),
                    "high": len([f for f in self.findings if f["severity"] == "high"]),
                    "medium": len([f for f in self.findings if f["severity"] == "medium"]),
                    "low": len([f for f in self.findings if f["severity"] == "low"])
                }
            }
            
            output_path = os.path.join(self.report_dir, "sqli_findings.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"[SQLi] Resultados exportados en: {output_path}")
            
        except Exception as e:
            self.logger.error(f"[SQLi] Error al exportar resultados: {e}")

    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
