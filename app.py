from flask import Flask, send_from_directory
import os

app = Flask(__name__)

@app.route('/crawl_tree')
def crawl_tree():
    return send_from_directory('templates', 'crawl_tree.html')

@app.route('/reports/<path:filename>')
def reports(filename):
    return send_from_directory('reports', filename)

if __name__ == '__main__':
    port = 5000
    print(f"\nServidor Flask iniciado en http://localhost:{port}/crawl_tree")
    print("Abre esa URL en tu navegador para visualizar el árbol de crawling.")
    app.run(port=port)
