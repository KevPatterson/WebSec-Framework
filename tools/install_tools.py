#!/usr/bin/env python3
"""
Script de instalación automática de herramientas de seguridad
Descarga e instala SQLMap, OWASP ZAP y Nuclei de forma completamente automática
"""
import os
import sys
import platform
import subprocess
import urllib.request
import zipfile
import shutil
from pathlib import Path

# Colores para terminal
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    
    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKCYAN = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''

# Deshabilitar colores en Windows si no soporta ANSI
if platform.system() == "Windows":
    try:
        import colorama
        colorama.init()
    except ImportError:
        Colors.disable()

def print_header(text):
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}{text}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

def print_success(text):
    print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {text}")

def print_info(text):
    print(f"{Colors.OKBLUE}[*]{Colors.ENDC} {text}")

def print_warning(text):
    print(f"{Colors.WARNING}[!]{Colors.ENDC} {text}")

def print_error(text):
    print(f"{Colors.FAIL}[-]{Colors.ENDC} {text}")

def download_file(url, dest_path, desc="archivo"):
    """Descarga un archivo con barra de progreso"""
    print_info(f"Descargando {desc}...")
    print_info(f"URL: {url}")
    
    try:
        def reporthook(count, block_size, total_size):
            if total_size > 0:
                percent = int(count * block_size * 100 / total_size)
                sys.stdout.write(f"\r  Progreso: {percent}% ")
                sys.stdout.flush()
        
        urllib.request.urlretrieve(url, dest_path, reporthook)
        print()  # Nueva línea después de la barra de progreso
        print_success(f"{desc} descargado correctamente")
        return True
    except Exception as e:
        print()
        print_error(f"Error al descargar {desc}: {e}")
        return False

def extract_zip(zip_path, extract_to):
    """Extrae un archivo ZIP"""
    print_info(f"Extrayendo archivos...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print_success("Archivos extraídos correctamente")
        return True
    except Exception as e:
        print_error(f"Error al extraer: {e}")
        return False

def check_command(command):
    """Verifica si un comando está disponible"""
    try:
        subprocess.run([command, "--version"], capture_output=True, timeout=5)
        return True
    except:
        return False

def install_sqlmap():
    """Instala SQLMap"""
    print_header("[1/3] Instalando SQLMap")
    
    tools_dir = Path("tools/sqlmap")
    tools_dir.mkdir(parents=True, exist_ok=True)
    
    # Verificar si ya está instalado
    if (tools_dir / "sqlmap.py").exists():
        print_success("SQLMap ya está instalado")
        return True
    
    # Intentar con Git primero
    if check_command("git"):
        print_info("Git encontrado. Clonando SQLMap...")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", 
                 "https://github.com/sqlmapproject/sqlmap.git", str(tools_dir)],
                check=True,
                capture_output=True
            )
            print_success("SQLMap instalado correctamente")
            return True
        except subprocess.CalledProcessError as e:
            print_error(f"Error al clonar: {e}")
    
    # Fallback: descargar ZIP
    print_info("Descargando SQLMap como ZIP...")
    zip_url = "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip"
    zip_path = "tools/sqlmap.zip"
    
    if download_file(zip_url, zip_path, "SQLMap"):
        if extract_zip(zip_path, "tools"):
            # Mover archivos
            src = Path("tools/sqlmap-master")
            if src.exists():
                for item in src.iterdir():
                    shutil.move(str(item), str(tools_dir))
                src.rmdir()
                os.remove(zip_path)
                print_success("SQLMap instalado correctamente")
                return True
    
    print_error("No se pudo instalar SQLMap")
    return False

def install_zap():
    """Instala OWASP ZAP en modo portable"""
    print_header("[2/3] Instalando OWASP ZAP")
    
    tools_dir = Path("tools/zap")
    tools_dir.mkdir(parents=True, exist_ok=True)
    
    # Verificar si ya está instalado
    is_windows = platform.system().lower().startswith("win")
    zap_bin = "zap.bat" if is_windows else "zap.sh"
    
    if (tools_dir / zap_bin).exists():
        print_success("ZAP ya está instalado")
        return True
    
    # Verificar instalación del sistema
    if is_windows:
        system_zap = Path("C:/Program Files/ZAP/zap.bat")
        if system_zap.exists():
            print_success("ZAP encontrado en instalación del sistema")
            return True
    
    # Verificar Java
    if not check_command("java"):
        print_warning("Java no detectado. ZAP requiere Java 11+")
        print_info("Descarga Java desde: https://adoptium.net/")
        print_info("Continuando con la instalación de ZAP...")
    else:
        print_success("Java encontrado")
    
    # Descargar versión portable
    print_info("Descargando ZAP Crossplatform (portable)...")
    print_warning("Esto puede tardar varios minutos (~200MB)")
    
    zap_version = "2.14.0"
    zip_url = f"https://github.com/zaproxy/zaproxy/releases/download/v{zap_version}/ZAP_{zap_version}_Crossplatform.zip"
    zip_path = "tools/zap.zip"
    
    if download_file(zip_url, zip_path, "ZAP"):
        print_info("Extrayendo ZAP (esto puede tardar un momento)...")
        if extract_zip(zip_path, "tools/zap_temp"):
            # Mover archivos
            src = Path(f"tools/zap_temp/ZAP_{zap_version}")
            if src.exists():
                for item in src.iterdir():
                    dest = tools_dir / item.name
                    if dest.exists():
                        if dest.is_dir():
                            shutil.rmtree(dest)
                        else:
                            dest.unlink()
                    shutil.move(str(item), str(tools_dir))
                
                # Limpiar
                shutil.rmtree("tools/zap_temp")
                os.remove(zip_path)
                
                # Dar permisos de ejecución en Linux/Mac
                if not is_windows:
                    zap_script = tools_dir / "zap.sh"
                    if zap_script.exists():
                        os.chmod(zap_script, 0o755)
                
                print_success("ZAP instalado correctamente en modo portable")
                return True
    
    print_error("No se pudo instalar ZAP")
    print_info("Puedes instalarlo manualmente desde: https://www.zaproxy.org/download/")
    return False

def install_nuclei():
    """Instala Nuclei"""
    print_header("[3/3] Instalando Nuclei")
    
    tools_dir = Path("tools/nuclei")
    tools_dir.mkdir(parents=True, exist_ok=True)
    
    is_windows = platform.system().lower().startswith("win")
    nuclei_bin = "nuclei.exe" if is_windows else "nuclei"
    
    # Verificar si ya está instalado
    if (tools_dir / nuclei_bin).exists():
        print_success("Nuclei ya está instalado")
        # Actualizar templates
        print_info("Actualizando templates de Nuclei...")
        try:
            subprocess.run([str(tools_dir / nuclei_bin), "-update-templates"], 
                         capture_output=True, timeout=60)
            print_success("Templates actualizados")
        except:
            print_warning("No se pudieron actualizar los templates")
        return True
    
    # Determinar URL de descarga según plataforma
    nuclei_version = "3.1.5"  # Actualiza según la última versión
    
    if is_windows:
        zip_name = f"nuclei_{nuclei_version}_windows_amd64.zip"
    elif platform.system() == "Darwin":
        zip_name = f"nuclei_{nuclei_version}_macOS_amd64.zip"
    else:
        zip_name = f"nuclei_{nuclei_version}_linux_amd64.zip"
    
    zip_url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{nuclei_version}/{zip_name}"
    zip_path = f"tools/{zip_name}"
    
    print_info(f"Descargando Nuclei para {platform.system()}...")
    
    if download_file(zip_url, zip_path, "Nuclei"):
        if extract_zip(zip_path, str(tools_dir)):
            os.remove(zip_path)
            
            # Dar permisos de ejecución en Linux/Mac
            if not is_windows:
                nuclei_path = tools_dir / nuclei_bin
                if nuclei_path.exists():
                    os.chmod(nuclei_path, 0o755)
            
            print_success("Nuclei instalado correctamente")
            
            # Actualizar templates
            print_info("Descargando templates de Nuclei...")
            try:
                subprocess.run([str(tools_dir / nuclei_bin), "-update-templates"], 
                             capture_output=True, timeout=60)
                print_success("Templates descargados")
            except:
                print_warning("No se pudieron descargar los templates")
            
            return True
    
    print_error("No se pudo instalar Nuclei")
    print_info("Puedes instalarlo manualmente desde: https://github.com/projectdiscovery/nuclei/releases")
    return False

def verify_installation():
    """Verifica que todas las herramientas estén instaladas"""
    print_header("Verificación de Instalación")
    
    tools_ok = 0
    
    # SQLMap
    print_info("Verificando SQLMap...")
    if Path("tools/sqlmap/sqlmap.py").exists():
        try:
            result = subprocess.run(
                [sys.executable, "tools/sqlmap/sqlmap.py", "--version"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print_success("SQLMap: OK")
                tools_ok += 1
            else:
                print_error("SQLMap: Instalado pero no funciona")
        except:
            print_error("SQLMap: Instalado pero no funciona")
    else:
        print_error("SQLMap: No instalado")
    
    # ZAP
    print_info("Verificando ZAP...")
    is_windows = platform.system().lower().startswith("win")
    zap_bin = "zap.bat" if is_windows else "zap.sh"
    
    zap_found = False
    if Path(f"tools/zap/{zap_bin}").exists():
        print_success("ZAP: OK (portable en tools/zap)")
        tools_ok += 1
        zap_found = True
    elif is_windows and Path("C:/Program Files/ZAP/zap.bat").exists():
        print_success("ZAP: OK (instalación del sistema)")
        tools_ok += 1
        zap_found = True
    
    if not zap_found:
        print_error("ZAP: No instalado")
    
    # Nuclei
    print_info("Verificando Nuclei...")
    nuclei_bin = "nuclei.exe" if is_windows else "nuclei"
    if Path(f"tools/nuclei/{nuclei_bin}").exists():
        try:
            result = subprocess.run(
                [f"tools/nuclei/{nuclei_bin}", "-version"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print_success("Nuclei: OK")
                tools_ok += 1
            else:
                print_error("Nuclei: Instalado pero no funciona")
        except:
            print_error("Nuclei: Instalado pero no funciona")
    else:
        print_error("Nuclei: No instalado")
    
    print()
    print(f"{Colors.BOLD}Resumen: {tools_ok}/3 herramientas instaladas correctamente{Colors.ENDC}")
    
    return tools_ok

def main():
    print_header("WebSec Framework - Instalador Automático de Herramientas")
    
    print("Este script instalará automáticamente:")
    print("  1. SQLMap (SQL Injection Scanner)")
    print("  2. OWASP ZAP (Web Application Scanner)")
    print("  3. Nuclei (Template-based Scanner)")
    print()
    
    # Crear directorio tools
    Path("tools").mkdir(exist_ok=True)
    
    # Instalar herramientas
    results = {
        "SQLMap": install_sqlmap(),
        "ZAP": install_zap(),
        "Nuclei": install_nuclei()
    }
    
    # Verificar instalación
    tools_ok = verify_installation()
    
    # Resumen final
    print_header("Instalación Completada")
    
    if tools_ok == 3:
        print_success("¡Todas las herramientas están instaladas y funcionando!")
        print()
        print_info("Puedes verificar la instalación ejecutando:")
        print(f"  {sys.executable} tests/test_external_tools.py")
    else:
        print_warning("Algunas herramientas no se instalaron correctamente.")
        print()
        print_info("Consulta la guía de instalación manual en:")
        print("  docs/INSTALL_TOOLS_WINDOWS.md")
    
    print()
    print_header("Configuración Recomendada")
    print()
    print("Actualiza tu archivo config/target.yaml con:")
    print()
    print("sqlmap_path: \"tools/sqlmap/sqlmap.py\"")
    print("zap_path: \"tools/zap/zap.bat\"  # o \"tools/zap/zap.sh\" en Linux/Mac")
    print("nuclei_path: \"tools/nuclei/nuclei.exe\"  # o \"tools/nuclei/nuclei\" en Linux/Mac")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print_warning("Instalación cancelada por el usuario")
        sys.exit(1)
    except Exception as e:
        print()
        print_error(f"Error inesperado: {e}")
        sys.exit(1)
