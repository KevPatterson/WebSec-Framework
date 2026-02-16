from flask import Flask, send_from_directory, jsonify, render_template_string
import os
import json

app = Flask(__name__)

# Obtener el último directorio de escaneo
def get_latest_scan_dir():
    reports_dir = 'reports'
    scan_dirs = [d for d in os.listdir(reports_dir) if d.startswith('scan_') and os.path.isdir(os.path.join(reports_dir, d))]
    if not scan_dirs:
        return None
    latest = sorted(scan_dirs)[-1]
    return os.path.join(reports_dir, latest)

@app.route('/')
def index():
    latest_scan = get_latest_scan_dir()
    if not latest_scan:
        return "No hay escaneos disponibles. Ejecuta un escaneo primero.", 404
    
    scan_name = os.path.basename(latest_scan)
    return f'''
    <html>
    <head>
        <title>WebSec Framework - Reportes</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0;
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                text-align: center;
                max-width: 600px;
            }}
            h1 {{
                color: #667eea;
                margin-bottom: 30px;
            }}
            .scan-info {{
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 30px;
            }}
            .btn {{
                display: inline-block;
                padding: 15px 30px;
                margin: 10px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                text-decoration: none;
                border-radius: 10px;
                font-weight: 600;
                transition: transform 0.3s;
            }}
            .btn:hover {{
                transform: translateY(-3px);
                box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 WebSec Framework</h1>
            <div class="scan-info">
                <h3>Último Escaneo</h3>
                <p><strong>{scan_name}</strong></p>
            </div>
            <a href="/crawl_tree/{scan_name}" class="btn">🌳 Ver Árbol de Crawling</a>
            <a href="/reports/{scan_name}/vulnerability_report.html" class="btn">📊 Ver Reporte de Vulnerabilidades</a>
        </div>
    </body>
    </html>
    '''

@app.route('/crawl_tree')
@app.route('/crawl_tree/')
def crawl_tree_redirect():
    latest_scan = get_latest_scan_dir()
    if not latest_scan:
        return "No hay escaneos disponibles. Ejecuta un escaneo primero.", 404
    scan_name = os.path.basename(latest_scan)
    return f'<script>window.location.href="/crawl_tree/{scan_name}";</script>'

@app.route('/crawl_tree/<scan_id>')
def crawl_tree(scan_id):
    return send_from_directory('templates', 'crawl_tree.html')

@app.route('/api/crawl_tree/<scan_id>')
def get_crawl_tree_json(scan_id):
    """Endpoint para servir el JSON del árbol de crawling"""
    try:
        json_path = os.path.join('reports', scan_id, 'crawl_tree.json')
        if not os.path.exists(json_path):
            return jsonify({'error': 'crawl_tree.json no encontrado. ¿Ejecutaste el escaneo con --no-crawl?'}), 404
        
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/reports/<path:filename>')
def reports(filename):
    return send_from_directory('reports', filename)

if __name__ == '__main__':
    port = 5000
    
    # Verificar que hay escaneos disponibles
    latest_scan = get_latest_scan_dir()
    
    print(f"\n{'='*60}")
    print(f"🚀 Servidor Flask iniciado en http://localhost:{port}/")
    print(f"{'='*60}")
    
    if latest_scan:
        scan_name = os.path.basename(latest_scan)
        print(f"\n📁 Último escaneo detectado: {scan_name}")
        
        # Verificar si tiene crawl_tree.json
        crawl_tree_path = os.path.join(latest_scan, 'crawl_tree.json')
        if os.path.exists(crawl_tree_path):
            print(f"   ✅ crawl_tree.json encontrado")
        else:
            print(f"   ⚠️  crawl_tree.json NO encontrado (escaneo con --no-crawl)")
        
        print(f"\n📊 Accede a:")
        print(f"   - Página principal: http://localhost:{port}/")
        if os.path.exists(crawl_tree_path):
            print(f"   - Árbol de crawling: http://localhost:{port}/crawl_tree/{scan_name}")
        print(f"   - Reporte HTML: http://localhost:{port}/reports/{scan_name}/vulnerability_report.html")
    else:
        print(f"\n⚠️  NO hay escaneos disponibles")
        print(f"   Ejecuta primero: python run.py https://example.com")
    
    print(f"\n{'='*60}")
    print(f"💡 Presiona Ctrl+C para detener el servidor")
    print(f"{'='*60}\n")
    
    app.run(port=port, debug=True)
