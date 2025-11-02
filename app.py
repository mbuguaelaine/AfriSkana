from flask import Flask, request, jsonify
from flask_cors import CORS 
from Security_Scanner import PortScanner, RecommendationEngine
import json
import time


app = Flask(__name__)

CORS(app) 


try:
    scanner = PortScanner()
    engine = RecommendationEngine()
    print("[*] Security Scanner Backend Intialized.")

except Exception as e:
    print(f"[ERROR] Failed to initialize core modules: {e}")
   
    scanner = None
    engine = None



@app.route('/api/scan', methods=['POST'])
def scan_network():
    
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No input data provided. Please send JSON"}), 400

        
        target_ip = data.get('target_ip')
        mode = data.get('scan_mode', 'standard') 

        if not target_ip:
            return jsonify({"error": "Missing 'target_ip' in request data"}), 400

    except Exception as e:
        
        return jsonify({"error": f"Invalid input data: {e}"}), 400

    
    if not scanner or not engine:
        return jsonify({"error": "Service not ready. Check server logs for initialization errors."}), 503

    
    scan_report = scanner.run_scan(target_ip, mode)

    if 'error' in scan_report:
        
        return jsonify({"error": scan_report['error']}), 500

    
    final_report = engine.analyze_report(scan_report)

    
    return jsonify(final_report), 200


if __name__ == '__main__':
   
    app.run(debug=True, port=5000)
