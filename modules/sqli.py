"""
Módulo de detección de SQL Injection.
Incluye detección básica y orquestación con SQLMap para explotación avanzada.
MIGRADO a EnhancedVulnerabilityModule - 60% menos código.
"""
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode
from core.enhanced_base_module import EnhancedVulnerabilityModule


class SQLiModule(EnhancedVulnerabilityModule):
    """
    Detecta vulnerabilidades SQL Injection.
    Soporta detección básica y orquestación con SQLMap.
    """
    
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

    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, PayloadManager, logger ya disponibles
        
        # Configuración específica
        self.max_tests_per_param = config.get('max_sqli_tests', 15)
        self.use_sqlmap = config.get("use_sqlmap", False)
        
        # Cargar payloads desde PayloadManager
        self.payloads = self._load_payloads('sqli', max_count=self.max_tests_per_param)
        
        # SQLMap runner
        self.sqlmap_runner = None
        if self.use_sqlmap:
            try:
                from core.external.sqlmap_runner import SqlmapRunner
                self.sqlmap_runner = SqlmapRunner(config)
            except Exception as e:
                self.logger.warning(f"[SQLi] No se pudo inicializar SQLMap: {e}")

    def scan(self):
        """Ejecuta el escaneo completo de SQLi."""
        self.logger.info(f"[SQLi] Iniciando escaneo de SQL Injection en: {self.target_url}")
        
        try:
            # 1. Detectar puntos de inyección (método heredado)
            injection_points = self._discover_injection_points()
            
            if not injection_points:
                self.logger.warning("[SQLi] No se encontraron puntos de inyección")
                return
            
            self.logger.info(f"[SQLi] Encontrados {len(injection_points)} puntos de inyección")
            
            # 2. Prueba básica de SQLi
            self._test_error_based_sqli(injection_points)
            self._test_boolean_based_sqli(injection_points)
            
            # 3. Si se encontraron vulnerabilidades y SQLMap está habilitado
            if self.findings and self.use_sqlmap and self.sqlmap_runner:
                self._run_sqlmap_on_findings()
            
            # 4. Exportar resultados (método heredado)
            self._export_results()
            
            # Resumen
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            
            self.logger.info(f"[SQLi] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[SQLi] Severidad: Critical={critical}, High={high}")
            
        except Exception as e:
            self.logger.error(f"[SQLi] Error inesperado: {e}")

    def _test_error_based_sqli(self, injection_points):
        """Prueba Error-based SQL Injection."""
        self.logger.info("[SQLi] Probando Error-based SQLi...")
        
        error_payloads = ["'", "\"", "' OR '1'='1", "1' AND '1'='2"]
        
        for point in injection_points:
            param = point['parameter']
            url = point['url']
            method = point['type']
            
            # Evitar duplicados
            param_key = f"{url}:{param}"
            if param_key in self.tested_params:
                continue
            self.tested_params.add(param_key)
            
            # Obtener respuesta baseline (método heredado)
            try:
                baseline = self._get_baseline_response(url, method)
            except:
                continue
            
            for payload in error_payloads:
                try:
                    # Hacer request con payload (método heredado)
                    if method == 'GET':
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        params[param] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                        response = self._make_request(test_url)
                    else:  # POST
                        data = {param: payload}
                        response = self._make_request(url, method='POST', data=data)
                    
                    if not response:
                        continue
                    
                    # Buscar errores SQL
                    sql_error = self._detect_sql_error(response.text)
                    
                    if sql_error:
                        # Añadir hallazgo (método heredado)
                        self._add_finding(
                            vulnerability=f"SQL Injection (Error-based) en parámetro '{param}'",
                            severity="critical",
                            url=url,
                            payload=payload,
                            details={
                                "parameter": param,
                                "method": method,
                                "type": "error_based_sqli",
                                "sql_error": sql_error,
                                "cvss": 9.8,
                                "cwe": "CWE-89",
                                "owasp": "A03:2021 - Injection",
                                "recommendation": "Usar consultas parametrizadas (prepared statements) o un ORM. Nunca concatenar entrada del usuario directamente en queries SQL.",
                                "references": [
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                                ]
                            }
                        )
                        
                        self.logger.warning(f"[SQLi] Error-based SQLi encontrado: {url} (param: {param})")
                        break
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.debug(f"[SQLi] Error probando {param}: {e}")

    def _test_boolean_based_sqli(self, injection_points):
        """Prueba Boolean-based SQL Injection."""
        self.logger.info("[SQLi] Probando Boolean-based SQLi...")
        
        for point in injection_points:
            param = point['parameter']
            url = point['url']
            method = point['type']
            
            # Evitar duplicados
            param_key = f"{url}:{param}:boolean"
            if param_key in self.tested_params:
                continue
            self.tested_params.add(param_key)
            
            try:
                # Obtener respuesta baseline (método heredado)
                baseline = self._get_baseline_response(url, method)
                if not baseline:
                    continue
                
                baseline_len = baseline['length']
                
                # Probar condición TRUE
                true_payload = "1' AND '1'='1"
                if method == 'GET':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param] = [true_payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                    true_response = self._make_request(test_url)
                else:
                    true_response = self._make_request(url, method='POST', data={param: true_payload})
                
                # Probar condición FALSE
                false_payload = "1' AND '1'='2"
                if method == 'GET':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param] = [false_payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                    false_response = self._make_request(test_url)
                else:
                    false_response = self._make_request(url, method='POST', data={param: false_payload})
                
                if not true_response or not false_response:
                    continue
                
                true_len = len(true_response.text)
                false_len = len(false_response.text)
                
                # Si las respuestas difieren significativamente, posible SQLi
                if abs(true_len - baseline_len) < 100 and abs(false_len - baseline_len) > 100:
                    # Añadir hallazgo (método heredado)
                    self._add_finding(
                        vulnerability=f"SQL Injection (Boolean-based) en parámetro '{param}'",
                        severity="high",
                        url=url,
                        details={
                            "parameter": param,
                            "method": method,
                            "type": "boolean_based_sqli",
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "baseline_length": baseline_len,
                            "true_length": true_len,
                            "false_length": false_len,
                            "cvss": 8.6,
                            "cwe": "CWE-89",
                            "owasp": "A03:2021 - Injection",
                            "recommendation": "Usar consultas parametrizadas (prepared statements). Implementar validación de entrada estricta.",
                            "references": [
                                "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                                "https://portswigger.net/web-security/sql-injection/blind"
                            ]
                        }
                    )
                    
                    self.logger.warning(f"[SQLi] Boolean-based SQLi encontrado: {url} (param: {param})")
                
                time.sleep(0.2)
                
            except Exception as e:
                self.logger.debug(f"[SQLi] Error probando boolean-based en {param}: {e}")

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
            if finding.get('details', {}).get('parameter'):
                url = finding.get('url')
                param = finding['details']['parameter']
                
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
