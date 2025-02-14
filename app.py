from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
from python.malware_analysis import scan_url_vt, get_url_report_vt, scan_file_vt, check_ip_abuseipdb

app = Flask(__name__)  # Corrected here
CORS(app)

# Routes for HTML files
@app.route('/')
def home():
    return send_from_directory('', 'home.html')

@app.route('/search.html')
def search():
    return send_from_directory('', 'search.html')

@app.route('/result.html')
def result():
    return send_from_directory('', 'result.html')

@app.route('/mitigation.html')
def mitigation():
    return send_from_directory('', 'mitigation.html')

@app.route('/login.html')
def login():
    return send_from_directory('', 'login.html')

@app.route('/signin.html')
def signin():
    return send_from_directory('', 'signin.html')

@app.route('/contact.html')
def contact():
    return send_from_directory('', 'contact.html')

@app.route('/chatbot.html')
def chatbot():
    return send_from_directory('', 'chatbot.html')

# Routes for static files
@app.route('/css/<path:path>')
def send_css(path):
    return send_from_directory('css', path)

@app.route('/js/<path:path>')
def send_js(path):
    return send_from_directory('js', path)

@app.route('/images/<path:path>')
def send_images(path):
    return send_from_directory('images', path)

# Chatbot endpoint
@app.route('/chat', methods=['POST'])
def chat():
    try:
        data = request.get_json()
        prompt = data.get('prompt')
        # Process the prompt here and generate a response
        response = "This is a response to: " + prompt
        return jsonify({"response": response})
    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"error": "An error occurred processing your request."}), 500

# Search API endpoint
@app.route('/api/search', methods=['POST'])
def search_api():
    search_type = request.form.get('searchType')
    result = {}

    try:
        if search_type == 'url':
            url = request.form.get('input')
            analysis_id = scan_url_vt(url)
            result = get_url_report_vt(analysis_id)
        elif search_type == 'ip':
            ip_address = request.form.get('input')
            result = check_ip_abuseipdb(ip_address)
        elif search_type == 'file':
            file = request.files['file']
            file_path = os.path.join('/tmp', file.filename)
            file.save(file_path)
            analysis_id = scan_file_vt(file_path)
            result = get_url_report_vt(analysis_id)
            os.remove(file_path)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify(result)

# Mitigation API endpoint
@app.route('/api/mitigation', methods=['POST'])
def mitigation_api():
    explanation = request.json.get('explanation')
    # Here you might want to process the explanation to get mitigation steps.
    # For simplicity, we'll just return a dummy mitigation response.
    mitigation_steps = {
        "steps": [
            "Step 1: Isolate the affected system.",
            "Step 2: Conduct a full malware scan.",
            "Step 3: Remove identified threats.",
            "Step 4: Apply necessary patches and updates.",
            "Step 5: Monitor the system for unusual activity."
        ]
    }
    return jsonify(mitigation_steps)

if __name__ == '__main__':  # Corrected here
    app.run(port=3000, debug=True)
