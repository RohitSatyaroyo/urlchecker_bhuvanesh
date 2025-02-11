from flask import Flask, render_template, request, jsonify
import requests
import validators
import urllib3
from urllib.parse import urlparse
import ssl
import socket
import OpenSSL
from datetime import datetime

app = Flask(__name__)

def check_ssl_cert(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return {
                    'valid': True,
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'issuer': dict(x[0] for x in cert['issuer'])['organizationName']
                }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }

def check_url_security(url):
    try:
        # Verify URL format
        if not validators.url(url):
            return {'valid': False, 'error': 'Invalid URL format'}

        # Parse URL
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc

        # Check if URL uses HTTPS
        is_https = parsed_url.scheme == 'https'

        # Make request to check if URL is accessible
        response = requests.head(url, allow_redirects=True, timeout=5, verify=True)
        status_code = response.status_code

        # Check SSL certificate if HTTPS
        ssl_info = check_ssl_cert(hostname) if is_https else {'valid': False, 'error': 'Not HTTPS'}

        return {
            'valid': True,
            'url': url,
            'is_https': is_https,
            'status_code': status_code,
            'ssl_valid': ssl_info['valid'],
            'ssl_info': ssl_info
        }

    except requests.exceptions.SSLError:
        return {'valid': False, 'error': 'SSL Certificate verification failed'}
    except requests.exceptions.RequestException as e:
        return {'valid': False, 'error': str(e)}
    except Exception as e:
        return {'valid': False, 'error': f'Unexpected error: {str(e)}'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.json.get('url', '')
    result = check_url_security(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)