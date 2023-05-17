from urllib.parse import urlparse
import requests
import re
import time
import bleach
from flask_compress import Compress
from flask import Flask, render_template, request
from flask_caching import Cache
import concurrent.futures

app = Flask(__name__)
Compress(app)

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url').strip()
    if not is_valid_url(url):
        error_message = "Invalid URL. Please enter a valid URL."
        return render_template('index.html', error_message=error_message)
    if not check_domain_existence(url):
        error_message = "Invalid URL. Please enter a valid domain."
        return render_template('index.html', error_message=error_message)

    vulnerabilities = check_vulnerabilities(url)
    return render_template('result.html', url=url, vulnerabilities=vulnerabilities)


def is_valid_url(url):
    """Verifica se uma url eh valida

    Args:
        url (String): Url para testar

    Returns:
        bool: Verificacao da url (true = existe, false = nao existe)
    """
    # Regex pattern to validate URL format
    url_pattern = re.compile(r'^(http|https)://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
    return re.match(url_pattern, url) is not None

def check_domain_existence(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    try:
        response = requests.head(url, timeout=5)
        if response.status_code == 200:
            return True
    except requests.exceptions.RequestException:
        return False

    return False

HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options"

def check_mimetype_sniffing(response):
    if response.headers.get(HEADER_X_CONTENT_TYPE_OPTIONS, "").lower() != "nosniff":
        return "Vulnerability: MIME sniffing"
    return None

SQLMAP_URL = "http://127.0.0.1:8775"

def create_task(url):
    sqlmap_url = SQLMAP_URL

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
            return task_id
        else:
            print("Erro ao iniciar a tarefa:", start_response.text)
    else:
        task_id = None
        print("Erro na solicitação POST para o sqlmap API:", task_response.text)

    return task_id

def check_task_status(task_id):
    sqlmap_url = SQLMAP_URL

    # Wait until the task is terminated
    timeout = 60  # seconds
    start_time = time.time()

    while time.time() - start_time < timeout:
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

def check_sql_injection(url):
    task_id = create_task(url)
    
    if task_id is not None:
        return check_task_status(task_id)

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

@cache.memoize(timeout=300)  # Cache results for 5 minutes
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
