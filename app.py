from flask import Flask, request, jsonify
from Security_Scanner import PortScanner, RecommendationEngine
import json
import time

# --- 1. Initialization ---
app = Flask(__name__)

# Intialize the scanner and engine once the app starts
# This prevents reloadinng the Nmap object and vulnerabilities database on every request
try:
    scanner = PortScanner()
    engine = RecommendationEngine()
    print("[*] Security Scanner Backend Intialized.")

except Exception as e:
    print(f"[ERROR] Failed to initialize core modules: {e}")
    # A placeholder initialization to prevent app crash, though the server won;t function

    scanner = None
    engine = None

# --- 2. API Endpoint Definition ---


@app.route('/scan', methods=['POST'])
def scan_network():
    # 3. Input Hnadling and Validation ---
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No input data provided. Please send JSON"}), 400

        target_ip = data.get('target_ip')
        # Default to 'standard' if not provided
        mode = data.get('mode', 'standard')

        if not target_ip:
            return jsonify({"error": "Missing 'target_ip' in request data"}), 400

    except Exception as e:
        # Handles non-JSON payloads or general parsing errors
        return jsonify({"error": f"Invalid input data: {e}"}), 400

    # Ensure services are initialized before running a scan
    if not scanner or not engine:
        return jsonify({"error": "Service not ready. Check server logs for initialization errors."}), 503

    # 4. Execure Scan (Week 1 Logic)
    scan_report = scanner.run_scan(target_ip, mode)

    if 'error' in scan_report:
        # Nmap failed (e.g., permissions, host unreachable)
        return jsonify({"error": scan_report['error']}), 500

    # 5. Analyze Results (week 2 logic)
    # The Recommendation Engine takes the raw scan data and adds intelligence
    final_report = engine.analyze_scan(scan_report)

    # 6. Return Response
    # Flask's Jsonify handles converting the Python dict to JSON response
    return jsonify(final_report), 200

   # Note: The server is run via 'Python -m flask run' outside of this script.
