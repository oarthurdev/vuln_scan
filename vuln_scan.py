from urllib.parse import urlparse
import requests
import re
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        vulnerabilities = perform_scan(url)
        return render_template('result.html', url=url, vulnerabilities=vulnerabilities)
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def perform_scan():
    if request.method == 'POST':
        url = request.form.get('url')

        # Check if the URL is valid
        if not is_valid_url(url):
            error_message = "Invalid URL. Please enter a valid URL."
            return render_template('index.html', error_message=error_message)

        vulnerabilities = check_vulnerabilities(url)

        # Render the result template with the URL and vulnerabilities
        return render_template('result.html', url=url, vulnerabilities=vulnerabilities)

def is_valid_url(url):
    # Regex pattern to validate URL format
    url_pattern = r'^(http|https)://[^\s/$.?#].[^\s]*$'
    return bool(re.match(url_pattern, url))

def check_mimetype_sniffing(response):
    if "X-Content-Type-Options" not in response.headers:
        return "Vulnerability: MIME sniffing"
    return None

def check_sql_injection(response):
    if "SQL" in response.text:
        return "Vulnerability: SQL Injection"
    return None

def check_xss_vulnerability(response):
    if "<script>" in response.text:
        return "Vulnerability: Cross-Site Scripting (XSS)"
    return None

def check_security_headers(response):
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection"
    ]

    vulnerabilities = []
    for header in security_headers:
        if header not in response.headers:
            vulnerabilities.append(f"Missing Security Header: {header}")

    return vulnerabilities

def check_command_injection(response):
    if "Command Injection" in response.text:
        return "Vulnerability: Command Injection"
    return None

def check_file_inclusion(response):
    if "File Inclusion" in response.text:
        return "Vulnerability: File Inclusion"
    return None

def check_vulnerabilities(url):
    response = requests.get(url)

    vulnerabilities = []
    vulnerabilities.append(check_mimetype_sniffing(response))
    vulnerabilities.append(check_sql_injection(response))
    vulnerabilities.append(check_xss_vulnerability(response))
    vulnerabilities.extend(check_security_headers(response))
    vulnerabilities.append(check_command_injection(response))
    vulnerabilities.append(check_file_inclusion(response))

    # Remove None values from the vulnerabilities list
    vulnerabilities = [vulnerability for vulnerability in vulnerabilities if vulnerability]

    return vulnerabilities

if __name__ == '__main__':
    app.run()
