from urllib.parse import urlparse
import requests
import re
import time
import bleach
from flask_compress import Compress
from flask import Flask, render_template, request
import concurrent.futures

app = Flask(__name__)
Compress(app)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        vulnerabilities = scan(url)
        return render_template('result.html', url=url, vulnerabilities=vulnerabilities)
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if request.method == 'POST':
        url = request.form.get('url')

        # Check domain existence
        if not check_domain_existence(url):
            error_message = "Invalid URL. Please enter a valid domain."
            return render_template('index.html', error_message=error_message)
    
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

def check_domain_existence(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    try:
        response = requests.head(url)
        if response.status_code == 200:
            return True
    except requests.exceptions.RequestException:
        return False

    return False

def check_mimetype_sniffing(response):
    if "X-Content-Type-Options" not in response.headers:
        return "Vulnerability: MIME sniffing"
    return None

def check_sql_injection(url):
    sqlmap_url = "http://127.0.0.1:8775"

    options = {
        'url': url,
        'batch': True,
        'level': 1,
        'risk': 1,
        'randomAgent': True
    }

    task_response = requests.get(f"{sqlmap_url}/task/new", json=options)

    if task_response.status_code == 200:
        task_id = task_response.json().get("taskid")
        start_task_url = f"{sqlmap_url}/scan/{task_id}/start"
        start_response = requests.post(start_task_url, json=options)

        if start_response.status_code == 200:
            print("Tarefa iniciada com sucesso.")
        else:
            print("Erro ao iniciar a tarefa:", start_response.text)
    else:
        task_id = None
        print("Erro na solicitação POST para o sqlmap API:", task_response.text)

    # Wait until the task is terminated
    while True:
        task_status_url = f"{sqlmap_url}/scan/{task_id}/status"
        status_response = requests.get(task_status_url)
        status_data = status_response.json()

        # Check if the task is terminated
        if status_data.get("status") == "terminated":
            task_details_url = f"{sqlmap_url}/scan/{task_id}/data"
            details_response = requests.get(task_details_url)
            details_data = details_response.json()

            # Check for SQL Injection vulnerability in the task details
            if details_data['data']:
                return "Vulnerability: SQL Injection"
            else:
                return []

        time.sleep(1)

    return None

def check_xss_vulnerability(response):
    cleaned_html = bleach.clean(response.text, tags=[], attributes={}, strip=True)
    if response.text != cleaned_html:
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

def check_vulnerabilities(url):
    headers = {
        'Accept-Encoding': 'gzip, deflate'
    }
    
    # Perform the request to get the response
    response = requests.get(url, headers=headers)

    vulnerabilities = []
    vulnerabilities.append(check_mimetype_sniffing(response))
    vulnerabilities.append(check_sql_injection(url))
    vulnerabilities.append(check_xss_vulnerability(response))
    vulnerabilities.extend(check_security_headers(response))

    vulnerabilities = [vulnerability for vulnerability in vulnerabilities if vulnerability]

    return vulnerabilities

if __name__ == '__main__':
    app.run(threaded=True)
