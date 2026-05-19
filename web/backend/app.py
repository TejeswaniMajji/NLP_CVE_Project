from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from model import predict_from_cve_id, predict_from_description
import os

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.get_json(force=True)
    if not data:
        return jsonify({'error': 'No input provided'}), 400
    cve_id = data.get('cve_id')
    description = data.get('description')
    if cve_id:
        result = predict_from_cve_id(cve_id)
        if 'error' in result:
            return jsonify({'error': result['error']}), 400
        return jsonify(result)
    if description:
        result = predict_from_description(description)
        return jsonify(result)
    return jsonify({'error': 'Provide cve_id or description'}), 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
