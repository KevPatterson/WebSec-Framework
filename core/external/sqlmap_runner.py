"""
Integración profesional con SQLMap (https://sqlmap.org/)
Permite ejecutar sqlmap en modo batch, parsear resultados y manejar múltiples targets.
"""
import os
import platform
import shutil
import subprocess
import json
import stat
import tempfile
from datetime import datetime
from core.logger import get_logger

class SqlmapRunner:
    """
    Clase para orquestar la ejecución de SQLMap desde el framework.
    - Busca el binario multiplataforma en ubicaciones estándar.
    - Soporta múltiples targets, POST data, cookies, headers.
    - Timeout configurable y argumentos extra.
    - Parsing robusto de resultados JSON y logs.
    """
    DEFAULT_TIMEOUT = 300

    def __init__(self, config):
        self.config = config
        self.logger = get_logger("sqlmap")
        self.sqlmap_path = config.get("sqlmap_path", "sqlmap")
        self.timeout = config.get("sqlmap_timeout", self.DEFAULT_TIMEOUT)

    def _find_sqlmap_exec(self):
        """Busca el ejecutable de sqlmap en múltiples ubicaciones."""
        is_windows = platform.system().lower().startswith("win")
        
        # Intentar encontrar sqlmap.py primero (versión Python)
        py_name = "sqlmap.py"
        search_paths_py = [
            shutil.which("sqlmap.py"),
            shutil.which("sqlmap"),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', py_name)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'sqlmap', py_name)),
            # Buscar en subdirectorios de sqlmap (por si se extrajo de ZIP)
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'sqlmap', 'sqlmapproject-sqlmap-*', py_name)),
        ]
        
        # Expandir wildcards para el último path
        import glob
        expanded_paths = []
        for path in search_paths_py:
            if path and '*' in path:
                expanded_paths.extend(glob.glob(path))
            elif path:
                expanded_paths.append(path)
        
        for path in expanded_paths:
            if path and os.path.isfile(path):
                return path, py_name, True  # True = es Python script
        
        # Si no se encuentra .py, buscar binario compilado
        bin_name = "sqlmap.exe" if is_windows else "sqlmap"
        search_paths_bin = [
            shutil.which(self.sqlmap_path),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', bin_name)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'sqlmap', bin_name)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'windows' if is_windows else 'linux', bin_name)),
        ]
        
        for path in search_paths_bin:
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
                return path, bin_name, False  # False = es binario
        
        return None, bin_name, False

    def run(self, target=None, data=None, extra_args=None, timeout=None, 
            risk=2, level=1, threads=1, technique=None, dbms=None, 
            cookie=None, headers=None, method=None, url_list=None,
            output_dir=None, tamper=None, random_agent=True):
        """
        Ejecuta sqlmap sobre uno o varios objetivos y retorna hallazgos.
        
        :param target: URL objetivo (str) o None si se usa url_list
        :param data: POST data (str)
        :param extra_args: lista de argumentos extra
        :param timeout: timeout de ejecución en segundos
        :param risk: nivel de riesgo (1-3)
        :param level: nivel de tests (1-5)
        :param threads: número de threads
        :param technique: técnicas SQL (B,E,U,S,T,Q)
        :param dbms: DBMS específico (MySQL, PostgreSQL, etc.)
        :param cookie: cookies para la petición
        :param headers: headers personalizados (dict o lista)
        :param method: método HTTP (GET, POST, etc.)
        :param url_list: lista de URLs o ruta a archivo
        :param output_dir: directorio de salida personalizado
        :param tamper: scripts de tamper (str o lista)
        :param random_agent: usar user-agent aleatorio
        :return: lista de hallazgos (dict)
        """
        sqlmap_exec, bin_name, is_python = self._find_sqlmap_exec()
        if not sqlmap_exec:
            self.logger.error(
                f"SQLMap no está instalado o no se encuentra en el PATH. "
                f"Descárgalo de https://github.com/sqlmapproject/sqlmap y colócalo en el PATH, "
                f"en la raíz del proyecto como {bin_name}, en tools/sqlmap/ o en windows/linux/. "
                f"También puedes configurar sqlmap_path en config."
            )
            return []

        # Preparar comando base
        if is_python:
            cmd = ["python", sqlmap_exec]
        else:
            cmd = [sqlmap_exec]

        # Configurar output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_dir:
            out_dir = output_dir
        else:
            out_dir = os.path.join("tmp_sqlmap", f"scan_{timestamp}")
        
        os.makedirs(out_dir, exist_ok=True)
        cmd += ["--batch", f"--output-dir={out_dir}"]

        # Target o lista de URLs
        if url_list:
            if isinstance(url_list, str) and os.path.isfile(url_list):
                cmd += ["-m", url_list]
            elif isinstance(url_list, (list, tuple)):
                with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as tmpf:
                    for u in url_list:
                        tmpf.write(u.strip() + "\n")
                    tmp_path = tmpf.name
                cmd += ["-m", tmp_path]
            else:
                self.logger.error("url_list debe ser una lista de URLs o ruta a archivo válido.")
                return []
        elif target:
            cmd += ["-u", target]
        else:
            self.logger.error("Debes especificar un target o una lista de URLs.")
            return []

        # Parámetros de configuración
        cmd += [f"--risk={risk}", f"--level={level}", f"--threads={threads}"]
        
        if random_agent:
            cmd += ["--random-agent"]
        
        if technique:
            cmd += [f"--technique={technique}"]
        
        if dbms:
            cmd += [f"--dbms={dbms}"]
        
        if data:
            cmd += ["--data", data]
        
        if method:
            cmd += [f"--method={method}"]
        
        if cookie:
            cmd += [f"--cookie={cookie}"]
        
        # Headers personalizados
        if headers:
            if isinstance(headers, dict):
                for k, v in headers.items():
                    cmd += ["--header", f"{k}: {v}"]
            elif isinstance(headers, (list, tuple)):
                for h in headers:
                    cmd += ["--header", str(h)]
        
        # Tamper scripts
        if tamper:
            if isinstance(tamper, (list, tuple)):
                cmd += [f"--tamper={','.join(tamper)}"]
            else:
                cmd += [f"--tamper={tamper}"]
        
        # Respuestas automáticas
        cmd += ["--flush-session", "--answers=follow=Y"]
        
        if extra_args:
            cmd += extra_args

        real_timeout = timeout if timeout else self.timeout
        self.logger.info(f"Ejecutando SQLMap: {' '.join(cmd)} (timeout={real_timeout}s)")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=real_timeout)
            
            if result.returncode != 0 and result.returncode != 1:  # 1 puede ser "no vulnerable"
                self.logger.warning(f"SQLMap retornó código {result.returncode}")
            
            if result.stderr:
                self.logger.debug(f"SQLMap stderr: {result.stderr.strip()}")
            
            # Parsear resultados
            findings = self._parse_sqlmap_output(out_dir, result.stdout)
            self.logger.info(f"SQLMap hallazgos: {len(findings)}")
            return findings
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout: SQLMap no respondió en {real_timeout} segundos.")
            return []
        except Exception as e:
            self.logger.error(f"Error ejecutando SQLMap: {e}")
            return []

    def _parse_sqlmap_output(self, output_dir, stdout):
        """
        Parsea los resultados de sqlmap desde archivos de log y stdout.
        """
        findings = []
        
        # Parsear stdout buscando vulnerabilidades
        if stdout:
            lines = stdout.split('\n')
            current_finding = {}
            
            for line in lines:
                line = line.strip()
                
                # Detectar inyecciones encontradas
                if "Parameter:" in line and "is vulnerable" in line.lower():
                    if current_finding:
                        findings.append(current_finding)
                    current_finding = {
                        "type": "SQL Injection",
                        "severity": "high",
                        "description": line,
                        "tool": "sqlmap"
                    }
                elif "Type:" in line and current_finding:
                    current_finding["injection_type"] = line.replace("Type:", "").strip()
                elif "Title:" in line and current_finding:
                    current_finding["title"] = line.replace("Title:", "").strip()
                elif "Payload:" in line and current_finding:
                    current_finding["payload"] = line.replace("Payload:", "").strip()
            
            if current_finding:
                findings.append(current_finding)
        
        # Buscar archivos de log en el directorio de salida
        if os.path.isdir(output_dir):
            for root, _, files in os.walk(output_dir):
                for f in files:
                    file_path = os.path.join(root, f)
                    
                    # Parsear archivos de log
                    if f.endswith(".log"):
                        try:
                            with open(file_path, "r", encoding="utf-8", errors="ignore") as log_file:
                                log_content = log_file.read()
                                if "is vulnerable" in log_content.lower():
                                    findings.append({
                                        "type": "SQL Injection",
                                        "severity": "high",
                                        "source": "log",
                                        "file": file_path,
                                        "tool": "sqlmap"
                                    })
                        except Exception as e:
                            self.logger.debug(f"Error leyendo log {file_path}: {e}")
                    
                    # Parsear archivos CSV de resultados
                    elif f.endswith(".csv"):
                        try:
                            with open(file_path, "r", encoding="utf-8") as csv_file:
                                import csv
                                reader = csv.DictReader(csv_file)
                                for row in reader:
                                    findings.append({
                                        "type": "SQL Injection",
                                        "severity": "high",
                                        "data": row,
                                        "source": "csv",
                                        "tool": "sqlmap"
                                    })
                        except Exception as e:
                            self.logger.debug(f"Error leyendo CSV {file_path}: {e}")
        
        return findings
