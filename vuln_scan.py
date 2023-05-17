from urllib.parse import urlparse
import requests
import re
import time
import bleach
from flask_compress import Compress
from flask import Flask, render_template, request

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


def check_sql_injection(url):
    # Execute a solicitação GET para obter a resposta
    response = requests.get(url)

    # Caso contrário, envie a solicitação para o sqlmap API
    sqlmap_url = "http://127.0.0.1:8775"  # Atualize com o URL correto do sqlmap API
    
    # Opções do SQLMap API
    options = {
        'url': url,  # Substitua target_url pela variável que contém a URL
        'batch': True,
        'level': 1,
        'risk': 1,
        'randomAgent': True
    }

    # Envie a solicitação POST para o sqlmap API para criar uma nova tarefa
    task_response = requests.get(f"{sqlmap_url}/task/new", json=options)

    if task_response.status_code == 200:
        task_id = task_response.json().get("taskid")
        # Inicie a tarefa manualmente
        start_task_url = f"{sqlmap_url}/scan/{task_id}/start"
        start_response = requests.post(start_task_url, json=options)

        print(start_response.content)
        if start_response.status_code == 200:
            print("Tarefa iniciada com sucesso.")
        else:
            print("Erro ao iniciar a tarefa:", start_response.text)
    else:
        # Lida com o erro na resposta do POST
        task_id = None
        print("Erro na solicitação POST para o sqlmap API:", task_response.text)

    print(task_id)

    # Aguarde até que a tarefa esteja concluída
    while True:
        # Consulte o status da tarefa usando o ID da tarefa
        task_status_url = f"{sqlmap_url}/scan/{task_id}/status"
        status_response = requests.get(task_status_url)
        status_data = status_response.json()

        print(status_data)

        # Verifique se a tarefa foi concluída
        if status_data.get("status") == "terminated":
            # Consulte os detalhes da tarefa concluída
            task_details_url = f"{sqlmap_url}/scan/{task_id}/data"
            details_response = requests.get(task_details_url)
            details_data = details_response.json()
        
            # Verifique se há uma vulnerabilidade de SQL Injection nos detalhes da tarefa
            if details_data['data'] != []:   
                return "Vulnerability: SQL Injection"
            else:
                return []

        # Aguarde um momento antes de verificar o status novamente
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

def check_command_injection(response):
    if "Command Injection" in response.text:
        return "Vulnerability: Command Injection"
    return None

def check_file_inclusion(response):
    if "File Inclusion" in response.text:
        return "Vulnerability: File Inclusion"
    return None

def check_vulnerabilities(url):
    headers = {
        'Accept-Encoding': 'gzip, deflate'
    }
    response = requests.get(url, headers=headers)

    vulnerabilities = []
    vulnerabilities.append(check_mimetype_sniffing(response))
    vulnerabilities.append(check_sql_injection(url))
    vulnerabilities.append(check_xss_vulnerability(response))
    vulnerabilities.extend(check_security_headers(response))
    vulnerabilities.append(check_command_injection(response))
    vulnerabilities.append(check_file_inclusion(response))

    # Remove None values from the vulnerabilities list
    vulnerabilities = [vulnerability for vulnerability in vulnerabilities if vulnerability]

    return vulnerabilities

if __name__ == '__main__':
    app.run()
