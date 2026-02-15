# Dependencias técnicas recomendadas para websec-framework

## Principales (core)
- requests>=2.31.0
- beautifulsoup4>=4.12.0
- jinja2>=3.1.2
- pyyaml>=6.0  # Configuración YAML
- colorlog>=6.7.0  # Logging colorido y profesional

## Opcionales/avanzadas
- playwright>=1.40.0  # Crawling JS dinámico (opcional)
- pytest>=7.4.0  # Testing

## Herramientas externas (integración)
- nuclei (descarga manual)
- sqlmap (descarga manual)
- zaproxy (descarga manual)

## Notas
- Todas las dependencias deben instalarse en entorno virtual Python 3.11+
- Las herramientas externas deben estar en PATH o configuradas en config/target.yaml
- No usar Docker, compatible con Windows y Linux

---
Este archivo debe mantenerse actualizado conforme evolucione el framework.