"""
Integración profesional con OWASP ZAP (https://www.zaproxy.org/)
Permite ejecutar escaneos en modo headless, API REST y parsear resultados JSON.
"""
import os
import platform
import shutil
import subprocess
import json
import stat
import time
import tempfile
from datetime import datetime
from core.logger import get_logger

class ZapRunner:
    """
    Clase para orquestar la ejecución de OWASP ZAP desde el framework.
    - Busca el binario multiplataforma en ubicaciones estándar.
    - Soporta modo quick scan, full scan y API REST.
    - Timeout configurable y argumentos extra.
    - Parsing robusto de resultados JSON, XML y HTML.
    """
    DEFAULT_TIMEOUT = 600
    DEFAULT_API_PORT = 8090

    def __init__(self, config):
        self.config = config
        self.logger = get_logger("zap")
        self.zap_path = config.get("zap_path", "zap.sh")
        self.timeout = config.get("zap_timeout", self.DEFAULT_TIMEOUT)
        self.api_port = config.get("zap_api_port", self.DEFAULT_API_PORT)
        self.api_key = config.get("zap_api_key", None)

    def _find_zap_exec(self):
        """Busca el ejecutable de ZAP en múltiples ubicaciones."""
        is_windows = platform.system().lower().startswith("win")
        
        # Nombres de binarios según plataforma
        if is_windows:
            bin_names = ["zap.bat", "zap.exe"]
        else:
            bin_names = ["zap.sh", "zap"]
        
        for bin_name in bin_names:
            search_paths = [
                shutil.which(bin_name),
                shutil.which(self.zap_path),
                # Instalación estándar de Windows
                os.path.abspath("C:\\Program Files\\ZAP\\zap.bat") if is_windows else None,
                os.path.abspath("C:\\Program Files (x86)\\ZAP\\zap.bat") if is_windows else None,
                # Versión portable en tools
                os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'zap', bin_name)),
                os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'zap', 'ZAP', bin_name)),
                # Otras ubicaciones
                os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', bin_name)),
                os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'zap', bin_name)),
                os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'windows' if is_windows else 'linux', bin_name)),
            ]
            
            # Filtrar None values
            search_paths = [p for p in search_paths if p is not None]
            
            for path in search_paths:
                if path and os.path.isfile(path):
                    # Validar permisos de ejecución en Linux
                    if not is_windows:
                        try:
                            st = os.stat(path)
                            if not (st.st_mode & stat.S_IXUSR):
                                self.logger.warning(f"El binario {path} no es ejecutable. Corrigiendo permisos...")
                                os.chmod(path, st.st_mode | stat.S_IXUSR)
                        except Exception as e:
                            self.logger.warning(f"No se pudo validar permisos: {e}")
                    return path, bin_name
        
        return None, bin_names[0]

    def run(self, target=None, extra_args=None, timeout=None, 
            scan_mode="quick", output_format="json", output_file=None,
            spider=True, ajax_spider=False, active_scan=True,
            context=None, user=None, url_list=None, config_file=None):
        """
        Ejecuta ZAP sobre uno o varios objetivos y retorna hallazgos.
        
        :param target: URL objetivo (str) o None si se usa url_list
        :param extra_args: lista de argumentos extra
        :param timeout: timeout de ejecución en segundos
        :param scan_mode: modo de escaneo (quick, full, baseline, api)
        :param output_format: formato de salida (json, xml, html, md)
        :param output_file: archivo de salida personalizado
        :param spider: ejecutar spider tradicional
        :param ajax_spider: ejecutar AJAX spider
        :param active_scan: ejecutar escaneo activo
        :param context: archivo de contexto ZAP
        :param user: usuario para autenticación
        :param url_list: lista de URLs o ruta a archivo
        :param config_file: archivo de configuración ZAP
        :return: lista de hallazgos (dict)
        """
        zap_exec, bin_name = self._find_zap_exec()
        if not zap_exec:
            self.logger.error(
                f"ZAP no está instalado o no se encuentra en el PATH. "
                f"Descárgalo de https://www.zaproxy.org/download/ y colócalo en el PATH, "
                f"en la raíz del proyecto como {bin_name}, en tools/zap/ o en windows/linux/. "
                f"También puedes configurar zap_path en config."
            )
            return []

        # Preparar directorio de salida
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_file:
            out_file = output_file
        else:
            out_dir = os.path.join("tmp_zap", f"scan_{timestamp}")
            os.makedirs(out_dir, exist_ok=True)
            out_file = os.path.join(out_dir, f"zap_report.{output_format}")

        # Construir comando según modo de escaneo
        if scan_mode == "quick":
            cmd = self._build_quick_scan_cmd(zap_exec, target, out_file, output_format)
        elif scan_mode == "baseline":
            cmd = self._build_baseline_scan_cmd(zap_exec, target, out_file, output_format)
        elif scan_mode == "full":
            cmd = self._build_full_scan_cmd(zap_exec, target, out_file, output_format, 
                                           spider, ajax_spider, active_scan)
        elif scan_mode == "api":
            cmd = self._build_api_scan_cmd(zap_exec, target, out_file, output_format)
        else:
            self.logger.error(f"Modo de escaneo desconocido: {scan_mode}")
            return []

        # Añadir contexto si se especifica
        if context and os.path.isfile(context):
            cmd += ["-n", context]

        # Añadir configuración si se especifica
        if config_file and os.path.isfile(config_file):
            cmd += ["-configfile", config_file]

        if extra_args:
            cmd += extra_args

        real_timeout = timeout if timeout else self.timeout
        self.logger.info(f"Ejecutando ZAP: {' '.join(cmd)} (timeout={real_timeout}s)")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=real_timeout)
            
            if result.returncode != 0:
                self.logger.warning(f"ZAP retornó código {result.returncode}")
            
            if result.stderr:
                self.logger.debug(f"ZAP stderr: {result.stderr.strip()}")
            
            # Parsear resultados
            findings = self._parse_zap_output(out_file, output_format, result.stdout)
            self.logger.info(f"ZAP hallazgos: {len(findings)}")
            return findings
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout: ZAP no respondió en {real_timeout} segundos.")
            return []
        except Exception as e:
            self.logger.error(f"Error ejecutando ZAP: {e}")
            return []

    def _build_quick_scan_cmd(self, zap_exec, target, out_file, output_format):
        """Construye comando para quick scan."""
        cmd = [zap_exec, "-cmd", "-quickurl", target, "-quickout", out_file]
        if output_format != "json":
            cmd += ["-quickprogress"]
        return cmd

    def _build_baseline_scan_cmd(self, zap_exec, target, out_file, output_format):
        """Construye comando para baseline scan."""
        is_windows = platform.system().lower().startswith("win")
        
        # ZAP baseline usa scripts Python
        if is_windows:
            baseline_script = os.path.join(os.path.dirname(zap_exec), "zap-baseline.py")
        else:
            baseline_script = os.path.join(os.path.dirname(zap_exec), "zap-baseline.py")
        
        if os.path.isfile(baseline_script):
            cmd = ["python", baseline_script, "-t", target, "-J", out_file]
        else:
            # Fallback a quick scan
            self.logger.warning("Script zap-baseline.py no encontrado, usando quick scan")
            cmd = self._build_quick_scan_cmd(zap_exec, target, out_file, output_format)
        
        return cmd

    def _build_full_scan_cmd(self, zap_exec, target, out_file, output_format,
                            spider, ajax_spider, active_scan):
        """Construye comando para full scan."""
        is_windows = platform.system().lower().startswith("win")
        
        # ZAP full scan usa scripts Python
        if is_windows:
            full_script = os.path.join(os.path.dirname(zap_exec), "zap-full-scan.py")
        else:
            full_script = os.path.join(os.path.dirname(zap_exec), "zap-full-scan.py")
        
        if os.path.isfile(full_script):
            cmd = ["python", full_script, "-t", target, "-J", out_file]
        else:
            # Fallback a modo daemon con comandos
            cmd = [zap_exec, "-daemon", "-port", str(self.api_port)]
            if self.api_key:
                cmd += ["-config", f"api.key={self.api_key}"]
        
        return cmd

    def _build_api_scan_cmd(self, zap_exec, target, out_file, output_format):
        """Construye comando para API scan."""
        is_windows = platform.system().lower().startswith("win")
        
        # ZAP API scan usa scripts Python
        if is_windows:
            api_script = os.path.join(os.path.dirname(zap_exec), "zap-api-scan.py")
        else:
            api_script = os.path.join(os.path.dirname(zap_exec), "zap-api-scan.py")
        
        if os.path.isfile(api_script):
            cmd = ["python", api_script, "-t", target, "-f", "openapi", "-J", out_file]
        else:
            # Fallback a baseline
            self.logger.warning("Script zap-api-scan.py no encontrado, usando baseline")
            cmd = self._build_baseline_scan_cmd(zap_exec, target, out_file, output_format)
        
        return cmd

    def _parse_zap_output(self, output_file, output_format, stdout):
        """
        Parsea los resultados de ZAP desde archivos de salida.
        """
        findings = []
        
        # Intentar leer archivo de salida
        if os.path.isfile(output_file):
            try:
                if output_format == "json":
                    with open(output_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        findings = self._extract_findings_from_json(data)
                elif output_format == "xml":
                    findings = self._parse_xml_output(output_file)
                elif output_format == "html":
                    findings = self._parse_html_output(output_file)
                else:
                    self.logger.warning(f"Formato no soportado para parsing: {output_format}")
            except Exception as e:
                self.logger.error(f"Error parseando archivo de salida {output_file}: {e}")
        
        # Parsear stdout si está disponible
        if stdout and not findings:
            findings = self._parse_stdout(stdout)
        
        return findings

    def _extract_findings_from_json(self, data):
        """Extrae hallazgos del JSON de ZAP."""
        findings = []
        
        # ZAP JSON puede tener diferentes estructuras
        if isinstance(data, dict):
            # Formato de reporte estándar
            if "site" in data:
                for site in data.get("site", []):
                    for alert in site.get("alerts", []):
                        findings.append({
                            "type": alert.get("alert", "Unknown"),
                            "severity": self._map_zap_risk(alert.get("riskcode", "0")),
                            "confidence": alert.get("confidence", "Unknown"),
                            "url": alert.get("url", ""),
                            "description": alert.get("desc", ""),
                            "solution": alert.get("solution", ""),
                            "reference": alert.get("reference", ""),
                            "cwe_id": alert.get("cweid", ""),
                            "wasc_id": alert.get("wascid", ""),
                            "tool": "zap"
                        })
            
            # Formato de alerta directa
            elif "alerts" in data:
                for alert in data.get("alerts", []):
                    findings.append({
                        "type": alert.get("alert", "Unknown"),
                        "severity": self._map_zap_risk(alert.get("riskcode", "0")),
                        "confidence": alert.get("confidence", "Unknown"),
                        "url": alert.get("url", ""),
                        "description": alert.get("desc", ""),
                        "solution": alert.get("solution", ""),
                        "tool": "zap"
                    })
        
        elif isinstance(data, list):
            # Lista de alertas
            for alert in data:
                if isinstance(alert, dict):
                    findings.append({
                        "type": alert.get("alert", alert.get("name", "Unknown")),
                        "severity": self._map_zap_risk(alert.get("riskcode", alert.get("risk", "0"))),
                        "url": alert.get("url", ""),
                        "description": alert.get("desc", alert.get("description", "")),
                        "tool": "zap"
                    })
        
        return findings

    def _map_zap_risk(self, risk_code):
        """Mapea códigos de riesgo de ZAP a severidades estándar."""
        risk_map = {
            "0": "info",
            "1": "low",
            "2": "medium",
            "3": "high",
            "4": "critical"
        }
        return risk_map.get(str(risk_code), "info")

    def _parse_xml_output(self, xml_file):
        """Parsea salida XML de ZAP."""
        findings = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for alert in root.findall(".//alertitem"):
                findings.append({
                    "type": alert.findtext("alert", "Unknown"),
                    "severity": self._map_zap_risk(alert.findtext("riskcode", "0")),
                    "url": alert.findtext("url", ""),
                    "description": alert.findtext("desc", ""),
                    "solution": alert.findtext("solution", ""),
                    "tool": "zap"
                })
        except Exception as e:
            self.logger.error(f"Error parseando XML: {e}")
        
        return findings

    def _parse_html_output(self, html_file):
        """Parsea salida HTML de ZAP (extracción básica)."""
        findings = []
        try:
            with open(html_file, "r", encoding="utf-8") as f:
                content = f.read()
                # Extracción básica - en producción usar BeautifulSoup
                if "High" in content or "Medium" in content:
                    findings.append({
                        "type": "Multiple vulnerabilities",
                        "severity": "medium",
                        "description": "Ver reporte HTML para detalles",
                        "file": html_file,
                        "tool": "zap"
                    })
        except Exception as e:
            self.logger.error(f"Error parseando HTML: {e}")
        
        return findings

    def _parse_stdout(self, stdout):
        """Parsea stdout buscando alertas."""
        findings = []
        lines = stdout.split('\n')
        
        for line in lines:
            line = line.strip()
            if "WARN" in line or "FAIL" in line or "alert" in line.lower():
                findings.append({
                    "type": "ZAP Alert",
                    "severity": "medium",
                    "description": line,
                    "tool": "zap"
                })
        
        return findings
