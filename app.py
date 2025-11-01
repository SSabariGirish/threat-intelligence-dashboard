import os
import requests
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv
import feedparser # For RSS News Feed

load_dotenv()
app = Flask(__name__, static_folder='public', static_url_path='')

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

NEWS_FEED_URL = "https://krebsonsecurity.com/feed/"

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    return send_from_directory(app.static_folder, path)

@app.route('/api/check-ip', methods=['POST'])
def check_ip():
    if not ABUSEIPDB_KEY:
        return jsonify({"error": "AbuseIPDB API key not configured"}), 500

    data = request.json
    ip_address = data.get('ip')
    if not ip_address:
        return jsonify({"error": "No IP address provided"}), 400

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_KEY}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 429:
            return jsonify({"error": "AbuseIPDB rate limit exceeded."}), 429
        elif response.status_code == 401:
            return jsonify({"error": "Invalid AbuseIPDB API key."}), 401
        else:
            return jsonify({"error": f"HTTP error from AbuseIPDB: {http_err}"}), response.status_code
    except Exception as e:
        print(f"Error checking IP: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/check-hash', methods=['POST'])
def check_hash():
    if not VIRUSTOTAL_KEY:
        return jsonify({"error": "VirusTotal API key not configured"}), 500

    data = request.json
    file_hash = data.get('hash')
    if not file_hash:
        return jsonify({"error": "No file hash provided"}), 400

    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'Accept': 'application/json', 'x-apikey': VIRUSTOTAL_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 404:
            return jsonify({"error": "Hash not found in VirusTotal database."}), 404

        response.raise_for_status()
        return jsonify(response.json())

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 429:
            return jsonify({"error": "VirusTotal rate limit exceeded."}), 429
        elif response.status_code == 401:
            return jsonify({"error": "Invalid VirusTotal API key."}), 401
        else:
            return jsonify({"error": f"HTTP error from VirusTotal: {http_err}"}), response.status_code
    except Exception as e:
        print(f"Error checking hash: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/cyber-news', methods=['GET'])
def get_cyber_news():
    try:
        feed = feedparser.parse(NEWS_FEED_URL)
        articles = []
        for entry in feed.entries[:20]:
            articles.append({
                'title': entry.title,
                'link': entry.link,
                'published': entry.published
            })
        return jsonify(articles)
    except Exception as e:
        print(f"Error fetching news feed: {e}")
        return jsonify({"error": "Could not fetch news feed"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)
