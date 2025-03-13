#!/usr/bin/env python3
import subprocess
import sys
import os
import re
import json
import time
import argparse
import random
import logging
import difflib
import csv
import threading
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin, urlencode
from typing import Dict, Any, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# MELHORIA 1: Verificação de dependências em vez de instalação automática
# Isso evita instalação não autorizada de pacotes, melhorando a segurança
def check_dependencies() -> None:
    """Verifica se todas as dependências necessárias estão instaladas."""
    missing = []
    try:
        import builtwith
    except ImportError:
        missing.append("builtwith")
    try:
        from Wappalyzer import Wappalyzer, WebPage
    except ImportError:
        missing.append("python-Wappalyzer")
    try:
        from colorama import Fore, Style, init
    except ImportError:
        missing.append("colorama")
    try:
        from tqdm import tqdm
    except ImportError:
        missing.append("tqdm")
    
    if missing:
        print(f"Dependências faltando: {', '.join(missing)}")
        print("Instale-as com: pip install " + " ".join(missing))
        sys.exit(1)

check_dependencies()

# Importações após verificação
import builtwith
from colorama import Fore, Style, init
init(autoreset=True)
from tqdm import tqdm

try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False
    logging.warning("Módulo 'python-Wappalyzer' não disponível.")

def log(message: str, level: str = 'INFO') -> None:
    """Função centralizada para logging com níveis diferentes."""
    if level.upper() == 'DEBUG':
        logging.debug(message)
    elif level.upper() == 'INFO':
        logging.info(message)
    elif level.upper() == 'WARNING':
        logging.warning(message)
    elif level.upper() == 'ERROR':
        logging.error(message)
    elif level.upper() == 'CRITICAL':
        logging.critical(message)
    else:
        logging.info(message)

# MELHORIA 3: Validação de entradas mais robusta
def validate_url(url: str) -> str:
    """Valida e normaliza uma URL de forma mais robusta."""
    url = url.strip()
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        raise ValueError("URL inválida: o esquema deve ser http ou https.")
    if not parsed.netloc:
        raise ValueError("URL inválida: domínio não especificado.")
    return url

def deep_update(source: Dict[Any, Any], overrides: Dict[Any, Any]) -> None:
    """Atualiza um dicionário de forma recursiva."""
    for key, value in overrides.items():
        if isinstance(value, dict) and key in source and isinstance(source[key], dict):
            deep_update(source[key], value)
        else:
            source[key] = value

def load_config(config_files: List[str]) -> Dict[str, Any]:
    """Carrega configurações de múltiplos arquivos JSON."""
    config: Dict[str, Any] = {}
    for file in config_files:
        if not os.path.exists(file):
            log(f"Arquivo de configuração '{file}' não encontrado.", level='WARNING')
            continue
        try:
            with open(file, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                deep_update(config, user_config)
                log(f"Configuração carregada de '{file}'", level='INFO')
        except json.JSONDecodeError as e:
            log(f"Erro de JSON no arquivo '{file}': {e}", level='ERROR')
    return config

def parse_query(input_str: str) -> Dict[str, str]:
    """Analisa uma string de consulta em um dicionário."""
    return {k: v[0] for k, v in parse_qs(input_str).items()} if input_str else {}

def parse_cookies(cookie_str: str) -> Dict[str, str]:
    """Analisa uma string de cookies em um dicionário."""
    if not cookie_str:
        return {}
    result = {}
    for cookie in cookie_str.split('; '):
        if '=' in cookie:
            key, value = cookie.split('=', 1)
            result[key] = value
    return result

def parse_headers(header_str: str) -> Dict[str, str]:
    """Analisa uma string de cabeçalhos em um dicionário."""
    if not header_str:
        return {}
    result = {}
    for header in header_str.split('; '):
        if ':' in header:
            key, value = header.split(':', 1)
            result[key.strip()] = value.strip()
    return result

def load_user_agents() -> List[str]:
    """Carrega uma lista de User-Agents mais atualizada."""
    return [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0'
    ]

# Classe para encapsular a resposta do curl
class CurlResponse:
    def __init__(self, status_code: int, headers: Dict[str, str], text: str):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.content = text.encode('utf-8')
        self.url = ""  # Será preenchido pela função send_request_curl

# MELHORIA 5: Implementação de cache para respostas HTTP
class ResponseCache:
    """Cache para armazenar respostas HTTP e evitar requisições repetidas."""
    def __init__(self, max_size: int = 100):
        self.cache: Dict[str, CurlResponse] = {}
        self.max_size = max_size
    
    def get(self, key: str) -> Optional[CurlResponse]:
        return self.cache.get(key)
    
    def set(self, key: str, value: CurlResponse) -> None:
        if len(self.cache) >= self.max_size:
            # Remove um item aleatório se o cache estiver cheio
            self.cache.pop(next(iter(self.cache)))
        self.cache[key] = value

# Instância global do cache
response_cache = ResponseCache()

def generate_cache_key(url: str, method: str, params: Optional[Dict[str, str]], 
                      data: Optional[Dict[str, str]]) -> str:
    """Gera uma chave única para o cache baseada nos parâmetros da requisição."""
    key_parts = [url, method]
    if params:
        key_parts.append(json.dumps(params, sort_keys=True))
    if data:
        key_parts.append(json.dumps(data, sort_keys=True))
    return hashlib.md5("|".join(key_parts).encode()).hexdigest()

def send_request_curl(url: str, method: str = "GET", params: Optional[Dict[str, str]] = None,
                      headers: Optional[Dict[str, str]] = None, cookies: Optional[Dict[str, str]] = None,
                      proxy: Optional[str] = None, timeout: Optional[float] = None,
                      data: Optional[Dict[str, str]] = None, use_cache: bool = True) -> CurlResponse:
    """
    Envia uma requisição HTTP usando curl e retorna um objeto CurlResponse.
    Implementa cache para evitar requisições repetidas.
    """
    # Verifica o cache primeiro se o uso de cache estiver habilitado
    if use_cache:
        cache_key = generate_cache_key(url, method, params, data)
        cached_response = response_cache.get(cache_key)
        if cached_response:
            return cached_response

    # Para GET, acrescenta os parâmetros na URL
    if method.upper() == "GET" and params:
        query_str = urlencode(params)
        url = url + ("&" if "?" in url else "?") + query_str
    
    command = ["curl", "-s", "-D", "-", url]
    
    if method.upper() != "GET":
        command.extend(["-X", method.upper()])
        if data or params:
            post_data = data if data else params
            post_data_str = urlencode(post_data)
            command.extend(["-d", post_data_str])
    
    if headers:
        for key, value in headers.items():
            command.extend(["-H", f"{key}: {value}"])
    
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        command.extend(["-b", cookie_str])
    
    if proxy:
        command.extend(["--proxy", proxy])
    
    if timeout:
        command.extend(["--max-time", str(timeout)])
    
    log(f"Executando comando: {' '.join(command)}", level="DEBUG")
    
    # MELHORIA 2: Melhor tratamento de exceções
    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except subprocess.SubprocessError as e:
        log(f"Erro ao executar curl: {e}", level="ERROR")
        raise
    except Exception as e:
        log(f"Erro inesperado ao executar curl: {e}", level="ERROR")
        raise
    
    output = result.stdout
    
    # Se houver redirecionamentos, curl pode retornar múltiplos blocos de cabeçalho
    parts = re.split(r'\r?\n\r?\n', output, maxsplit=10)
    if len(parts) >= 2:
        header_block = parts[-3] if len(parts) > 2 else parts[0]
        body = parts[-1]
    else:
        header_block = ""
        body = output
    
    headers_dict = {}
    status_code = 0
    
    lines = header_block.splitlines()
    if lines:
        status_line = lines[0]
        match = re.search(r'HTTP/\S+\s+(\d+)', status_line)
        if match:
            status_code = int(match.group(1))
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers_dict[key.strip()] = value.strip()
    
    response = CurlResponse(status_code, headers_dict, body)
    response.url = url
    
    # Armazena no cache se o uso de cache estiver habilitado
    if use_cache:
        response_cache.set(cache_key, response)
    
    return response

# Padrões de erro SQL para identificação de vulnerabilidades
# MELHORIA: Lista expandida de padrões para melhor detecção
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlstate",
    r"ora-\d{5}",
    r"mysql_fetch_array",
    r"mysql_num_rows",
    r"odbc_exec",
    r"syntax error at line \d+",
    r"microsoft sql server error",
    r"postgresql query failed",
    r"division by zero in sql statement",
    r"supplied argument is not a valid mysql",
    r"column .* not found",
    r"pg_query\(\): query failed"
]

# Padrões para detecção de XSS
XSS_PATTERNS = [
    r".*?",
    r"]+onerror=",
    r"javascript:",
    r"onload=",
    r"onclick=",
    r"onmouseover="
]

def check_sql_errors(response_text: str) -> bool:
    """Verifica se a resposta contém mensagens de erro SQL."""
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False

def check_xss_reflection(response_text: str, payload: str) -> bool:
    """Verifica se um payload XSS foi refletido na resposta."""
    # Verifica se o payload está presente na resposta
    if payload in response_text:
        # Verifica se o payload não foi sanitizado (ainda contém tags HTML)
        sanitized = re.sub(r"]*>", "", payload)
        if sanitized != payload and payload in response_text:
            return True
    return False

def analyze_http_headers(headers: Dict[str, str]) -> List[str]:
    """Analisa cabeçalhos HTTP em busca de problemas de segurança."""
    issues = []
    security_headers = {
        "X-Frame-Options": "Protege contra ataques de clickjacking",
        "X-XSS-Protection": "Ajuda a prevenir ataques XSS em navegadores antigos",
        "Content-Security-Policy": "Restringe fontes de conteúdo para prevenir XSS e injeções",
        "Strict-Transport-Security": "Força conexões HTTPS",
        "X-Content-Type-Options": "Previne MIME-sniffing",
        "Referrer-Policy": "Controla informações de referência enviadas",
        "Permissions-Policy": "Restringe recursos do navegador"
    }
    
    for sh, description in security_headers.items():
        if sh not in headers:
            issues.append(f"Falta header de segurança: {sh} ({description})")
    
    if "Server" in headers:
        server = headers["Server"]
        if any(old_version in server for old_version in ["Apache/1.", "Apache/2.0", "Apache/2.2", "nginx/1.0", "IIS/5", "IIS/6"]):
            issues.append(f"Versão potencialmente vulnerável do servidor: {server}")
    
    if "X-Powered-By" in headers:
        issues.append(f"Header 'X-Powered-By' expõe tecnologia: {headers['X-Powered-By']}")
    
    return issues

# MELHORIA 4: Detecção de WAF
def detect_waf(response: CurlResponse) -> Optional[str]:
    """Detecta a presença de Web Application Firewall."""
    waf_signatures = {
        "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "ModSecurity": ["mod_security", "NOYB"],
        "Imperva": ["incap_ses", "visid_incap", "imperva"],
        "Akamai": ["akamaighost"],
        "F5 BIG-IP": ["BigIP", "F5"],
        "Sucuri": ["sucuri"],
        "Wordfence": ["wordfence"],
        "AWS WAF": ["aws-waf"],
        "Barracuda": ["barracuda"]
    }
    
    headers_str = str(response.headers).lower()
    for waf_name, signatures in waf_signatures.items():
        for signature in signatures:
            if signature.lower() in headers_str:
                return waf_name
    
    # Verificar no corpo da resposta
    for waf_name, signatures in waf_signatures.items():
        for signature in signatures:
            if signature.lower() in response.text.lower():
                return waf_name
    
    return None

# MELHORIA 8: Análise diferencial mais sofisticada
class ResponseAnalyzer:
    @staticmethod
    def compare_responses(resp1: CurlResponse, resp2: CurlResponse) -> Dict[str, Any]:
