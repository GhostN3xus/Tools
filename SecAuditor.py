#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import aiohttp
import argparse
import logging
import logging.handlers
import re
import json
import time
import html
import base64
import os
from urllib.parse import urlparse, urljoin, quote, parse_qsl, urlencode
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup

# Integração opcional com Selenium para renderização dinâmica
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

###############################################
# Configurações (padrão, podendo ser sobrescritas)
###############################################
class Config:
    HEADERS = {
        "User-Agent": "SecAuditor/6.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }
    MAX_DEPTH = 3
    TIMEOUT = 10
    RETRY_ATTEMPTS = 3
    RETRY_DELAY = 2  # segundos
    REQUESTS_PER_SECOND = 5
    LOG_LEVEL = logging.DEBUG
    LOG_FILE = "auditoria.log"
    REPORT_FORMATS = ["json", "html"]
    USE_SELENIUM = False  # Renderização dinâmica via Selenium
    PAYLOADS_FILE = None  # Arquivo JSON com payloads customizados (opcional)

###############################################
# Configuração do Sistema de Logs com Rotação
###############################################
def configurar_logs():
    logger = logging.getLogger()
    logger.setLevel(Config.LOG_LEVEL)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    # Handler para arquivo com rotação (máximo de 5MB por arquivo, 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(Config.LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logging.info("Sistema de logs configurado com rotação.")

###############################################
# Função para carregar configurações de payloads a partir de arquivo JSON
###############################################
def carregar_payloads_do_arquivo(caminho):
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            data = json.load(f)
            logging.info(f"Payloads customizados carregados de {caminho}")
            return data
    except Exception as e:
        logging.error(f"Erro ao carregar payloads do arquivo: {e}")
        return {}

###############################################
# Função auxiliar: Verificação do robots.txt
###############################################
def pode_acessar(url, user_agent=Config.HEADERS["User-Agent"]):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    rp = RobotFileParser()
    rp.set_url(urljoin(base, "/robots.txt"))
    try:
        rp.read()
    except Exception as e:
        logging.warning(f"Falha ao ler robots.txt em {base}: {e}")
        return True
    return rp.can_fetch(user_agent, url)

###############################################
# Função opcional: Renderização dinâmica com Selenium
###############################################
def renderizar_com_selenium(url):
    if not SELENIUM_AVAILABLE:
        logging.error("Selenium não está instalado; renderização dinâmica não disponível.")
        return None
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        html_content = driver.page_source
        driver.quit()
        logging.info(f"Página renderizada dinamicamente via Selenium: {url}")
        return html_content
    except Exception as e:
        logging.error(f"Erro no Selenium para {url}: {e}")
        return None

###############################################
# Função para análise avançada de resposta
###############################################
def analisar_resposta(body):
    patterns = {
        "SQL": [r"SQL syntax.*MySQL", r"Warning.*mssql_", r"ORA-\d+", r"SQLSTATE"],
        "PHP": [r"PHP Parse error", r"Fatal error", r"Warning: include\("],
        "File Inclusion": [r"failed to open stream", r"No such file or directory"],
        "Command": [r"command not found", r"not recognized as an internal or external command"],
        "Directory Traversal": [r"\.\./\.\./", r"../../", r"directory not found", r"Forbidden"]
    }
    detected = {}
    for category, regexes in patterns.items():
        for regex in regexes:
            if re.search(regex, body, re.IGNORECASE):
                detected.setdefault(category, []).append(regex)
    return detected

###############################################
# Crawler Assíncrono (Site Mapper)
###############################################
class AsyncSiteMapper:
    def __init__(self, base_url, max_depth=None):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth if max_depth is not None else Config.MAX_DEPTH
        self.visited = {}          # URL normalizada -> dados (status, erros, etc.)
        self.forms = []            # formulários encontrados
        self.internal_urls = set() # URLs internas deduplicadas
        self.metadados = {}        # meta tags
        self.recursos = {}         # scripts, estilos, imagens
        self.tecnologias = {}      # tecnologias detectadas
        self.conteudo = {}         # análise textual

        self.semaphore = asyncio.Semaphore(Config.REQUESTS_PER_SECOND)
        self.session = None

    async def _fetch(self, url):
        if not pode_acessar(url):
            logging.info(f"Bloqueado pelo robots.txt: {url}")
            return None
        async with self.semaphore:
            for attempt in range(Config.RETRY_ATTEMPTS):
                try:
                    async with self.session.get(url, timeout=Config.TIMEOUT) as response:
                        text = await response.text()
                        logging.debug(f"URL acessada: {url} - Status {response.status}")
                        return response.status, text, response.headers
                except Exception as e:
                    logging.warning(f"Erro ao acessar {url} (tentativa {attempt+1}): {e}")
                    await asyncio.sleep(Config.RETRY_DELAY)
            logging.error(f"Falha definitiva ao acessar {url}")
            return None

    def _normalize_url(self, url):
        parsed = urlparse(url)
        # Normaliza: remove query string e fragmentos para deduplicação
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    
    def _is_internal_url(self, url):
        parsed_base = urlparse(self.base_url)
        parsed_target = urlparse(url)
        return (parsed_target.netloc == "" or parsed_target.netloc == parsed_base.netloc)

    def _process_page(self, url, html_text, headers):
        soup = BeautifulSoup(html_text, "lxml")
        self._coletar_formularios(url, soup)
        self._extrair_metadados(url, soup)
        self._coletar_recursos(url, soup)
        self._detectar_tecnologias(url, html_text, headers)
        self._analisar_conteudo(url, soup)
        links = self._coletar_links(url, soup)
        return links

    def _coletar_formularios(self, url, soup):
        for form in soup.find_all("form"):
            method = form.get("method", "GET").upper()
            action = form.get("action", "")
            action = urljoin(url, action)
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                ttype = inp.get("type", "text")
                inputs.append((name, ttype))
            self.forms.append({
                "url": url,
                "action": action,
                "method": method,
                "inputs": inputs
            })
            logging.debug(f"Formulário detectado: {action} (método: {method})")

    def _coletar_links(self, url, soup):
        links = []
        for tag in soup.find_all("a"):
            href = tag.get("href")
            if href:
                full_url = urljoin(url, href)
                if self._is_internal_url(full_url):
                    links.append(full_url)
        return links

    def _extrair_metadados(self, url, soup):
        metadados = {}
        metadados['title'] = soup.title.string.strip() if soup.title and soup.title.string else None
        desc = soup.find('meta', attrs={'name': 'description'})
        metadados['description'] = desc.get('content') if desc else None
        keyw = soup.find('meta', attrs={'name': 'keywords'})
        metadados['keywords'] = keyw.get('content') if keyw else None
        self.metadados[url] = metadados

    def _coletar_recursos(self, url, soup):
        scripts = [urljoin(url, script.get('src')) for script in soup.find_all('script', src=True)]
        styles = [urljoin(url, link.get('href')) for link in soup.find_all('link', rel='stylesheet')]
        images = [urljoin(url, img.get('src')) for img in soup.find_all('img', src=True)]
        self.recursos[url] = {'scripts': scripts, 'styles': styles, 'images': images}

    def _detectar_tecnologias(self, url, html_text, headers):
        tecnologias = []
        if 'X-Powered-By' in headers:
            tecnologias.append(headers['X-Powered-By'])
        if 'Server' in headers:
            tecnologias.append(headers['Server'])
        soup = BeautifulSoup(html_text, "lxml")
        for script in soup.find_all('script', src=True):
            src = script.get('src', '').lower()
            if 'jquery' in src:
                tecnologias.append('jQuery')
            elif 'bootstrap' in src:
                tecnologias.append('Bootstrap')
            elif 'react' in src:
                tecnologias.append('React')
            elif 'vue' in src:
                tecnologias.append('Vue.js')
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            tecnologias.append(generator.get('content'))
        self.tecnologias[url] = list(set(tecnologias))

    def _analisar_conteudo(self, url, soup):
        from collections import Counter
        texto = soup.get_text(separator=" ", strip=True)
        palavras = re.findall(r'\w+', texto.lower())
        contagem = Counter(palavras)
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', texto)
        tokens = re.findall(r'[a-zA-Z0-9]{32,}', texto)
        self.conteudo[url] = {
            'total_palavras': len(palavras),
            'palavras_frequentes': contagem.most_common(10),
            'emails_encontrados': emails,
            'possiveis_tokens': tokens
        }

    async def mapear(self, url=None, depth=0):
        if depth > self.max_depth:
            return
        if url is None:
            url = self.base_url

        norm_url = self._normalize_url(url)
        if norm_url in self.visited:
            return

        result = await self._fetch(url)
        if not result:
            self.visited[norm_url] = {"status": None, "error": "Falha na requisição"}
            return

        status, text, headers = result
        self.visited[norm_url] = {"status": status}
        if status != 200:
            return

        # Se habilitado, usa Selenium para renderizar páginas dinâmicas
        if Config.USE_SELENIUM:
            rendered = renderizar_com_selenium(url)
            if rendered:
                text = rendered

        links = self._process_page(url, text, headers)
        for link in links:
            norm_link = self._normalize_url(link)
            if norm_link not in self.visited and self._is_internal_url(link):
                self.internal_urls.add(norm_link)
                await self.mapear(link, depth + 1)

    async def iniciar(self):
        async with aiohttp.ClientSession(headers=Config.HEADERS) as session:
            self.session = session
            await self.mapear(self.base_url)

    def resultado(self):
        return {
            "visited_urls": self.visited,
            "forms": self.forms,
            "internal_urls": list(self.internal_urls),
            "metadados": self.metadados,
            "recursos": self.recursos,
            "tecnologias": self.tecnologias,
            "conteudo": self.conteudo
        }

###############################################
# Inspeção de Formulários
###############################################
class InputInspector:
    @staticmethod
    def detectar_tipo_campo(nome, tipo_html):
        tipo_html = tipo_html.lower() if tipo_html else "text"
        nome = nome.lower() if nome else ""
        mapping = {
            "email": "email",
            "file": "file",
            "hidden": "hidden",
            "number": "number",
            "password": "password",
            "tel": "telephone",
            "url": "url",
            "date": "date",
            "time": "time",
            "datetime-local": "datetime",
            "month": "month",
            "week": "week",
            "color": "color",
            "range": "range",
            "search": "search",
            "checkbox": "checkbox",
            "radio": "radio"
        }
        if tipo_html in mapping:
            return mapping[tipo_html]
        if "email" in nome:
            return "email"
        if "senha" in nome or "password" in nome:
            return "password"
        if "telefone" in nome or "phone" in nome:
            return "telephone"
        if "data" in nome or "date" in nome:
            return "date"
        if "cor" in nome or "color" in nome:
            return "color"
        if "url" in nome:
            return "url"
        return "text"

    @staticmethod
    def analisar(forms):
        for form in forms:
            form["detected_types"] = []
            for nome, tipo in form.get("inputs", []):
                detected = InputInspector.detectar_tipo_campo(nome, tipo)
                form["detected_types"].append((nome, detected))
            form["security_analysis"] = InputInspector.analisar_seguranca(form["detected_types"])
        return forms

    @staticmethod
    def analisar_seguranca(detected_types):
        analysis = []
        for nome, tipo in detected_types:
            recs = []
            if tipo == "password":
                recs.extend(["Política de senhas fortes", "Uso de HTTPS"])
            elif tipo == "email":
                recs.extend(["Validação de formato", "Verificação de e-mail"])
            elif tipo == "file":
                recs.extend(["Limitar tipos de arquivo", "Escanear uploads"])
            elif tipo == "hidden":
                recs.append("Verificar dados sensíveis")
            analysis.append({"campo": nome, "tipo": tipo, "recomendações": recs})
        return analysis

###############################################
# Gerador de Payloads e Mutações
###############################################
class PayloadGenerator:
    # Payloads padrão para diversas categorias
    BASE_PAYLOADS = {
        "SQLi": [
            "' OR 1=1 --",
            "' UNION SELECT null --",
            "'; DROP TABLE users; --",
            "1' ORDER BY 1--+",
            "1;SELECT SLEEP(5)--"
        ],
        "XSS": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>"
        ],
        "CMDi": [
            "&& uname -a",
            "; ls -la",
            "| whoami"
        ],
        "LFI": [
            "../../../etc/passwd",
            "/etc/passwd",
            "/var/www/../../etc/passwd"
        ],
        "SSRF": [
            "http://127.0.0.1/admin",
            "http://localhost:8080",
            "http://169.254.169.254/latest/meta-data/"
        ],
        "RCE": [
            "system('id')",
            "exec('ls')",
            "os.system('whoami')"
        ],
        "Directory Traversal": [
            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "/../../../../etc/shadow"
        ]
    }

    @staticmethod
    def gerar_payloads_teste(categorias=None):
        payloads = {}
        if Config.PAYLOADS_FILE:
            # Se um arquivo de payloads for especificado, carrega payloads customizados
            custom_payloads = carregar_payloads_do_arquivo(Config.PAYLOADS_FILE)
            payloads.update(custom_payloads)
        # Mescla os payloads padrão, sobrescrevendo se já existirem
        if not categorias:
            categorias = list(PayloadGenerator.BASE_PAYLOADS.keys())
        for cat in categorias:
            payloads.setdefault(cat, PayloadGenerator.BASE_PAYLOADS.get(cat, []))
        return payloads

    @staticmethod
    def mutar_payloads(payload):
        mutations = set([payload])
        mutations.add(quote(payload))
        mutations.add(html.escape(payload))
        mutations.add(base64.b64encode(payload.encode()).decode())
        mutations.add(payload.replace(" ", "%20"))
        mutations.add(payload.replace(" ", "+"))
        mutations.add(payload.replace("'", "\""))
        mutations.add(payload.replace("\"", "'"))
        return list(mutations)

###############################################
# Injector: Teste de Injeção em Múltiplas Áreas e Métodos
###############################################
class Injector:
    def __init__(self):
        self.logs = []
        self.http_methods = ["GET", "POST", "PUT", "DELETE"]
        self.injection_areas = ["params", "data", "headers", "cookies"]

    async def testar_formulario(self, sessao, form, payload):
        for method in self.http_methods:
            for area in self.injection_areas:
                kwargs = {}
                if area == "params":
                    kwargs["params"] = {nome: payload for nome, _ in form.get("inputs", []) if nome}
                elif area == "data":
                    kwargs["data"] = {nome: payload for nome, _ in form.get("inputs", []) if nome}
                elif area == "headers":
                    kwargs["headers"] = {"X-Test-Injection": payload}
                elif area == "cookies":
                    kwargs["cookies"] = {"test_injection": payload}
                try:
                    async with sessao.request(method, form["action"], timeout=Config.TIMEOUT, **kwargs) as resp:
                        status = resp.status
                        body = await resp.text()
                        erros = analisar_resposta(body)
                        suspeita = status is None or status >= 500 or bool(erros)
                        log_entry = {
                            "form": form,
                            "payload": payload,
                            "http_method": method,
                            "injection_area": area,
                            "status": status,
                            "erros_detectados": erros,
                            "alerta": "Possível vulnerabilidade" if suspeita else ""
                        }
                        self.logs.append(log_entry)
                        if suspeita:
                            logging.warning(f"Alerta: {form['action']} com payload {payload} ({method} em {area}) - Erros: {erros}")
                except Exception as e:
                    log_entry = {
                        "form": form,
                        "payload": payload,
                        "http_method": method,
                        "injection_area": area,
                        "status": None,
                        "erros_detectados": {},
                        "alerta": f"Erro: {e}"
                    }
                    self.logs.append(log_entry)
                    logging.error(f"Erro: {form['action']} com payload {payload} ({method} em {area}) - {e}")

    async def executar_testes_injecao(self, forms, payloads_categorias):
        async with aiohttp.ClientSession(headers=Config.HEADERS) as sessao:
            tasks = []
            for form in forms:
                for categoria, payload_list in payloads_categorias.items():
                    for payload in payload_list:
                        for mutated in PayloadGenerator.mutar_payloads(payload):
                            tasks.append(self.testar_formulario(sessao, form, mutated))
            await asyncio.gather(*tasks)

###############################################
# Geração de Relatórios
###############################################
class ReportManager:
    @staticmethod
    def gerar_relatorio_json(arquivo, dados):
        try:
            with open(arquivo, "w", encoding="utf-8") as f:
                json.dump(dados, f, indent=2, ensure_ascii=False)
            logging.info(f"Relatório JSON gerado: {arquivo}")
        except Exception as e:
            logging.error(f"Erro ao gerar relatório JSON: {e}")

    @staticmethod
    def gerar_relatorio_html(arquivo, logs):
        conteudo = [
            "<html><head><meta charset='utf-8'><title>Relatório de Auditoria</title></head><body>",
            "<h1>Relatório de Auditoria</h1>",
            "<ul>"
        ]
        for item in logs:
            conteudo.append("<li>")
            conteudo.append(f"<strong>Form:</strong> {item['form']['action']}<br>")
            conteudo.append(f"<strong>Payload:</strong> {item['payload']}<br>")
            conteudo.append(f"<strong>Método:</strong> {item['http_method']}<br>")
            conteudo.append(f"<strong>Área de Injeção:</strong> {item['injection_area']}<br>")
            conteudo.append(f"<strong>Status:</strong> {item['status']}<br>")
            if item['erros_detectados']:
                conteudo.append(f"<strong>Erros:</strong> {item['erros_detectados']}<br>")
            if item['alerta']:
                conteudo.append(f"<strong>Alerta:</strong> {item['alerta']}<br>")
            conteudo.append("</li>")
        conteudo.append("</ul>")
        conteudo.append("</body></html>")
        try:
            with open(arquivo, "w", encoding="utf-8") as f:
                f.write("\n".join(conteudo))
            logging.info(f"Relatório HTML gerado: {arquivo}")
        except Exception as e:
            logging.error(f"Erro ao gerar relatório HTML: {e}")

###############################################
# Função Principal com Integração CLI
###############################################
async def main(args):
    # Se um arquivo de configuração for fornecido, atualiza as variáveis de ambiente
    if args.config:
        try:
            with open(args.config, "r", encoding="utf-8") as f:
                conf = json.load(f)
                for key, value in conf.items():
                    setattr(Config, key.upper(), value)
            logging.info(f"Configuração carregada de {args.config}")
        except Exception as e:
            logging.error(f"Erro ao carregar arquivo de configuração: {e}")

    # Atualiza configurações via CLI
    Config.MAX_DEPTH = args.depth
    Config.TIMEOUT = args.timeout
    Config.LOG_FILE = args.log
    Config.REPORT_FORMATS = args.report
    Config.USE_SELENIUM = args.selenium
    if args.payloads_file:
        Config.PAYLOADS_FILE = args.payloads_file

    configurar_logs()
    logging.info("Iniciando auditoria...")

    # Inicia o crawler assíncrono
    mapper = AsyncSiteMapper(args.url, max_depth=Config.MAX_DEPTH)
    await mapper.iniciar()
    resultado_map = mapper.resultado()
    logging.info(f"Total de URLs mapeadas: {len(resultado_map['visited_urls'])}")
    logging.info(f"Total de formulários encontrados: {len(resultado_map['forms'])}")

    # Analisa formulários
    forms_analisados = InputInspector.analisar(resultado_map["forms"])
    # Gera payloads customizados (mescla payloads padrão e os do arquivo, se houver)
    payloads_categorias = PayloadGenerator.gerar_payloads_teste(["SQLi", "XSS", "CMDi", "LFI", "SSRF", "RCE", "Directory Traversal"])
    # Executa testes de injeção
    injector = Injector()
    await injector.executar_testes_injecao(forms_analisados, payloads_categorias)
    logging.info(f"Testes de injeção concluídos. Total de entradas registradas: {len(injector.logs)}")

    # Geração de relatórios
    timestamp = int(time.time())
    if "json" in Config.REPORT_FORMATS:
        ReportManager.gerar_relatorio_json(f"relatorio_{timestamp}.json", injector.logs)
    if "html" in Config.REPORT_FORMATS:
        ReportManager.gerar_relatorio_html(f"relatorio_{timestamp}.html", injector.logs)
    logging.info("Auditoria finalizada.")

###############################################
# Execução via CLI
###############################################
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ferramenta de Auditoria e Mapeamento de Sites - Versão 6.0",
        epilog="Exemplo: python auditoria.py --url http://localhost --depth 3 --timeout 10 --log auditoria.log --report json html --selenium --payloads_file payloads.json --config config.json"
    )
    parser.add_argument("--url", required=True, help="URL base para iniciar a auditoria (ex: http://localhost)")
    parser.add_argument("--depth", type=int, default=3, help="Profundidade máxima para o crawler (padrão: 3)")
    parser.add_argument("--timeout", type=int, default=10, help="Tempo máximo de espera por requisição (padrão: 10)")
    parser.add_argument("--log", type=str, default="auditoria.log", help="Caminho do arquivo de log (padrão: auditoria.log)")
    parser.add_argument("--report", type=str, choices=["json", "html", "pdf"], nargs="+", default=["json", "html"],
                        help="Formatos de relatório a serem gerados (ex: --report json html)")
    parser.add_argument("--selenium", action="store_true", help="Habilita o uso do Selenium para renderização dinâmica de páginas")
    parser.add_argument("--payloads_file", type=str, help="Caminho para arquivo JSON com payloads customizados (opcional)")
    parser.add_argument("--config", type=str, help="Caminho para arquivo JSON de configuração (opcional)")
    args = parser.parse_args()

    asyncio.run(main(args))
