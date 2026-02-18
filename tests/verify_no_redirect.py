#!/usr/bin/env python3
"""
Verifica que el reporte HTML no contenga redirecciones no deseadas.
"""

import re
import os

def verify_no_redirect(html_path):
    """Verifica que no haya redirecciones en el HTML."""
    
    print(f"🔍 Verificando: {html_path}")
    
    if not os.path.exists(html_path):
        print(f"❌ Archivo no encontrado: {html_path}")
        return False
    
    with open(html_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Patrones peligrosos que podrían causar redirección
    dangerous_patterns = [
        (r'window\.location\s*=', 'window.location ='),
        (r'location\.href\s*=', 'location.href ='),
        (r'location\.replace\(', 'location.replace('),
        (r'<meta[^>]*http-equiv=["\']refresh["\']', 'meta refresh'),
        (r'document\.location\s*=', 'document.location ='),
    ]
    
    issues_found = []
    
    for pattern, description in dangerous_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            # Verificar si está en un comentario o string escapado
            for match in matches:
                # Buscar contexto
                idx = content.find(match)
                context = content[max(0, idx-100):min(len(content), idx+100)]
                
                # Si no está en un comentario HTML o JavaScript
                if not ('<!--' in context or '//' in context or '/*' in context):
                    issues_found.append(f"  ⚠️  {description}: {match}")
    
    # Verificar que los POCs estén escapados
    unescaped_script = re.findall(r'<script>(?!.*&lt;)', content)
    if unescaped_script:
        # Verificar si son scripts legítimos del reporte
        legitimate_scripts = [
            'Chart.js',
            'showTab',
            'toggleDetails',
            'filterFindings',
            'exportJSON',
            'var reportData',
            'var summaryData'
        ]
        
        for script_content in unescaped_script:
            is_legitimate = any(leg in content[content.find(script_content):content.find(script_content)+500] 
                              for leg in legitimate_scripts)
            if not is_legitimate:
                issues_found.append(f"  ⚠️  Script no escapado encontrado")
    
    # Verificar que los POCs estén correctamente escapados
    escaped_pocs = re.findall(r'&lt;script&gt;', content)
    print(f"✅ POCs escapados encontrados: {len(escaped_pocs)}")
    
    escaped_forms = re.findall(r'&lt;form', content)
    print(f"✅ Formularios escapados encontrados: {len(escaped_forms)}")
    
    escaped_iframes = re.findall(r'&lt;iframe', content)
    print(f"✅ iframes escapados encontrados: {len(escaped_iframes)}")
    
    if issues_found:
        print("\n❌ Problemas encontrados:")
        for issue in issues_found:
            print(issue)
        return False
    else:
        print("\n✅ No se encontraron redirecciones ni código no escapado")
        print("✅ El reporte es seguro para abrir en el navegador")
        return True

if __name__ == '__main__':
    html_path = 'reports/test_exploitation_report.html'
    verify_no_redirect(html_path)
