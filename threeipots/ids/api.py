from flask import Flask, jsonify
from flask_cors import CORS
import subprocess

app = Flask(__name__)
# Autoriser uniquement ton frontend
CORS(app, origins=["http://localhost:5173"], supports_credentials=True)

DETECTION_SCRIPT = 'ids.py'
process = None

@app.route('/api/toggle', methods=['POST'])
def toggle():
    global process
    if process and process.poll() is None:
        process.terminate()
        process = None
        return jsonify({'running': False})
    process = subprocess.Popen(['python', DETECTION_SCRIPT])
    return jsonify({'running': True})

@app.route('/api/status')
def status():
    return jsonify({'running': process is not None and process.poll() is None})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
