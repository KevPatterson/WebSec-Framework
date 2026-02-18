# Integración de Nmap en WebSec Framework

## 📋 Descripción

El framework ahora incluye integración completa con **Nmap** para escaneo de puertos, detección de servicios y fingerprinting de sistemas operativos. La integración utiliza la librería `python-nmap` para una comunicación nativa con Nmap desde Python.

## 🚀 Instalación

### 1. Instalar Nmap en el Sistema

**Windows:**
```bash
# Descargar e instalar desde: https://nmap.org/download.html
# O usar Chocolatey:
choco install nmap
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**Linux (RedHat/CentOS):**
```bash
sudo yum install nmap
```

**macOS:**
```bash
brew install nmap
```

### 2. Instalar python-nmap

```bash
pip install python-nmap
```

O instalar todas las dependencias:
```bash
pip install -r requirements.txt
```

### 3. Verificar Instalación

```bash
nmap --version
```

## 📊 Características

### Tipos de Escaneo Disponibles

1. **Quick Scan** (Rápido)
   - Escanea puertos comunes (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443)
   - Detección de servicios y versiones
   - Tiempo estimado: 1-2 minutos

2. **Full Scan** (Completo)
   - Escanea todos los puertos (1-65535)
   - Detección de servicios y versiones
   - Opción de detección de OS (requiere privilegios)
   - Tiempo estimado: 10-30 minutos

3. **Service Scan** (Servicios)
   - Escaneo enfocado en detección de servicios
   - Scripts NSE para información detallada
   - Puertos configurables

4. **Vulnerability Scan** (Vulnerabilidades)
   - Ejecuta scripts de vulnerabilidades de Nmap
   - Detección de CVEs conocidos
   - Análisis de configuraciones inseguras

## 🔧 Uso

### Uso Básico desde run.py

```bash
# Escaneo rápido de puertos
python run.py https://example.com --nmap

# Escaneo completo
python run.py https://example.com --nmap --nmap-scan-type full

# Escaneo de servicios
python run.py https://example.com --nmap --nmap-scan-type service

# Escaneo de vulnerabilidades
python run.py https://example.com --nmap --nmap-scan-type vuln

# Escaneo con puertos personalizados
python run.py https://example.com --nmap --nmap-ports "80,443,8080,8443"

# Escaneo con detección de OS (requiere sudo/admin)
python run.py https://example.com --nmap --nmap-detect-os
```

### Uso Programático

```python
from core.external.nmap_runner import NmapRunner

# Inicializar
config = {"nmap_timeout": 300}
nmap_runner = NmapRunner(config)

# Escaneo rápido
results = nmap_runner.quick_scan("example.com")

# Escaneo completo con detección de OS
results = nmap_runner.full_scan("example.com", detect_os=True)

# Escaneo de servicios
results = nmap_runner.service_scan("example.com", ports="1-1000")

# Escaneo de vulnerabilidades
results = nmap_runner.vulnerability_scan("example.com", ports="80,443")

# Obtener resumen de puertos abiertos
summary = nmap_runner.get_open_ports_summary(results)

# Exportar resultados
nmap_runner.export_results(results, "reports/nmap_results.json")
```

### Uso del Módulo PortScanModule

```python
from modules.port_scan import PortScanModule

# Configuración
config = {
    "target_url": "https://example.com",
    "nmap_scan_type": "quick",  # quick, full, service, vuln
    "nmap_ports": "1-1000",     # Opcional
    "nmap_detect_os": False     # Requiere privilegios
}

# Ejecutar escaneo
module = PortScanModule(config)
module.scan()

# Obtener hallazgos
findings = module.get_results()
```

## 📁 Estructura de Resultados

### Archivo: `port_scan_findings.json`

```json
{
  "scan_info": {
    "target": "https://example.com",
    "timestamp": "20260218_120000",
    "module": "port_scan",
    "scan_type": "quick",
    "total_findings": 5
  },
  "findings": [
    {
      "type": "open_port",
      "severity": "info",
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "title": "Puerto Abierto: 80/tcp - http (nginx 1.18.0)",
      "description": "Se detectó el puerto 80/tcp abierto ejecutando http (nginx 1.18.0)",
      "recommendation": "Asegurar HTTP: usar HTTPS (443), implementar security headers...",
      "cvss": 0.0,
      "evidence": {
        "host": "93.184.216.34",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "product": "nginx",
        "version": "1.18.0",
        "extrainfo": "",
        "cpe": "cpe:/a:nginx:nginx:1.18.0"
      }
    }
  ],
  "summary": {
    "high": 1,
    "medium": 2,
    "low": 0,
    "info": 2
  }
}
```

### Archivo: `nmap_scan_results.json`

Contiene los resultados completos del escaneo de Nmap con toda la información técnica.

## 🎯 Severidades y Recomendaciones

### Puertos Críticos (High)
- **23 (Telnet)**: Protocolo inseguro, usar SSH
- **445 (SMB)**: Vulnerable a ataques, asegurar configuración
- **3389 (RDP)**: Expuesto a ataques de fuerza bruta

### Puertos de Riesgo Medio (Medium)
- **21 (FTP)**: Usar SFTP o FTPS
- **22 (SSH)**: Asegurar con autenticación por clave
- **3306 (MySQL)**: Limitar acceso remoto
- **5432 (PostgreSQL)**: Configurar correctamente

### Recomendaciones Generales
1. Cerrar puertos innecesarios
2. Usar firewalls para limitar acceso
3. Mantener servicios actualizados
4. Implementar autenticación fuerte
5. Usar cifrado (TLS/SSL)
6. Monitorear logs de acceso

## ⚙️ Configuración Avanzada

### Opciones de Configuración

```python
config = {
    # Ruta personalizada de nmap (opcional)
    "nmap_path": "/usr/bin/nmap",
    
    # Timeout en segundos (default: 300)
    "nmap_timeout": 600,
    
    # Tipo de escaneo: quick, full, service, vuln
    "nmap_scan_type": "quick",
    
    # Puertos personalizados
    "nmap_ports": "1-1000",
    
    # Detección de OS (requiere privilegios)
    "nmap_detect_os": False,
    
    # Directorio de reportes
    "report_dir": "reports/scan_20260218_120000"
}
```

### Argumentos de Nmap

El módulo utiliza los siguientes argumentos según el tipo de escaneo:

- **Quick**: `-sV -T4` (detección de servicios, velocidad normal)
- **Full**: `-sV -T4 -A` (detección completa con OS)
- **Service**: `-sV -sC` (servicios + scripts por defecto)
- **Vuln**: `-sV --script vuln` (scripts de vulnerabilidades)

## 🔒 Consideraciones de Seguridad

### Permisos Requeridos

Algunos escaneos requieren privilegios elevados:
- Detección de OS (`-O`)
- SYN scan (`-sS`)
- Algunos scripts NSE

**Linux/macOS:**
```bash
sudo python run.py https://example.com --nmap --nmap-detect-os
```

**Windows:**
Ejecutar como Administrador

### Legalidad y Ética

⚠️ **IMPORTANTE**: Solo escanea sistemas que:
1. Te pertenecen
2. Tienes autorización explícita para escanear
3. Están en un entorno de pruebas controlado

El escaneo no autorizado puede ser ilegal en tu jurisdicción.

## 🐛 Troubleshooting

### Error: "python-nmap no está instalado"
```bash
pip install python-nmap
```

### Error: "Nmap no está disponible"
Instala Nmap en tu sistema operativo (ver sección de instalación)

### Error: "Permission denied"
Algunos escaneos requieren privilegios de administrador:
```bash
sudo python run.py ... --nmap
```

### Escaneo muy lento
- Usa `--nmap-scan-type quick` para escaneos rápidos
- Reduce el rango de puertos con `--nmap-ports`
- Aumenta el timeout si es necesario

## 📚 Referencias

- [Nmap Official Documentation](https://nmap.org/book/man.html)
- [python-nmap Documentation](https://xael.org/pages/python-nmap-en.html)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [OWASP Testing Guide - Port Scanning](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage)

## 🔄 Integración con Otros Módulos

El módulo de Nmap se integra perfectamente con:
- **Fingerprinting**: Complementa la detección de tecnologías
- **Vulnerability Scanning**: Identifica servicios vulnerables
- **Reporting**: Los hallazgos se incluyen en reportes HTML/PDF

## 📊 Ejemplo de Reporte

Los hallazgos de Nmap se incluyen automáticamente en:
- `vulnerability_scan_consolidated.json`
- `vulnerability_report.html`
- `vulnerability_report.pdf` (con --export-pdf)

Con información detallada sobre:
- Puertos abiertos
- Servicios y versiones
- Sistema operativo detectado
- Recomendaciones de seguridad
- CVSS scoring

## 🎓 Mejores Prácticas

1. **Escaneo Progresivo**: Empieza con quick, luego full si es necesario
2. **Horarios**: Escanea en horarios de bajo tráfico
3. **Documentación**: Mantén registro de escaneos autorizados
4. **Análisis**: Revisa todos los puertos abiertos, no solo los críticos
5. **Seguimiento**: Re-escanea periódicamente para detectar cambios
6. **Correlación**: Combina con otros módulos para análisis completo

## 🆕 Próximas Mejoras

- [ ] Soporte para escaneo de rangos de IPs
- [ ] Integración con bases de datos de vulnerabilidades
- [ ] Detección automática de servicios desactualizados
- [ ] Comparación de escaneos históricos
- [ ] Alertas automáticas para puertos críticos
- [ ] Exportación a formatos adicionales (XML, CSV)
