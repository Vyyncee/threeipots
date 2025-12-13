from flask import Flask, jsonify
from flask_cors import CORS
import subprocess
import os
import sys


app = Flask(__name__)
# Autoriser uniquement ton frontend
CORS(app, origins=["http://localhost:5173"], supports_credentials=True)

DETECTION_SCRIPT = './threeipots/ids/ids.py'
parent_dir = '/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data'
process = None

@app.route('/api/toggle', methods=['POST'])
def toggle():
    global process

    # Si le processus existe et est actif, on l'arrête
    if process and process.poll() is None:
        process.terminate()
        process.wait()  # Attendre que le process se termine correctement
        process = None
        return jsonify({'running': False})

    env = os.environ.copy()
    env['PYTHONPATH'] = parent_dir

    # Lancer le script IDS en processus détaché
    process = subprocess.Popen(
        ['python', DETECTION_SCRIPT],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True
    )

    return jsonify({'running': True})

@app.route('/api/status')
def status():
    return jsonify({'running': process is not None and process.poll() is None})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
