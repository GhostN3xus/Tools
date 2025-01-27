# Ferramenta de Auditoria de Segurança

Ferramenta avançada e extensível para análise de segurança em aplicações web, focada em:

- **Mapeamento de URLs e formulários**
- **Validação de entradas**
- **Injeção de payloads com mutações avançadas**
- **Análise de respostas do servidor**
- **Geração de relatórios em formatos configuráveis**

**Atenção:** Utilize somente em ambientes controlados e com autorização prévia.

---

## Recursos Principais

- **Mapeamento automático de URLs** até profundidades configuráveis.
- **Coleta e inspeção de formulários**, detectando tipos de campos (texto, e-mail, etc.).
- **Geração e mutação de payloads** para testar diversas categorias de vulnerabilidades, como SQL Injection, XSS e Command Injection.
- **Relatórios nos formatos HTML e JSON**, exibindo todas as tentativas de injeção e resultados encontrados.

---

## Requisitos

- **Python 3.6+ instalado**

### Bibliotecas Python:

- `requests`
- `beautifulsoup4`

*(Opcional)* Ter um proxy configurado caso queira interceptar requisições (Burp, Zap, etc.).

---

## Instalação

1. **Clone o repositório:**

   ```bash
   git clone https://github.com/GhostN3xus/Tools.git
   ```

2. **Acesse a pasta do projeto:**

   ```bash
   cd Tools
   ```

3. **Instale as dependências necessárias:**

   ```bash
   pip install -r requirements.txt
   ```

---

## Painel de Ajuda

Exiba a ajuda com o comando:

```bash
python SecAuditor.py -h
```

---

## Lista de Argumentos

| **Argumento**   | **Descrição**                                                      |
| --------------- | ------------------------------------------------------------------ |
| `-u, --url`     | Define a URL base para auditoria (obrigatório).                    |
| `-d, --depth`   | Define a profundidade máxima do mapeamento (padrão: 3).            |
| `-t, --timeout` | Tempo limite (em segundos) para cada requisição HTTP (padrão: 10). |
| `--use-proxy`   | Ativa o uso de proxy configurado no código (ex.: Burp/ZAP).        |
| `-f, --formats` | Define os formatos dos relatórios gerados (`html`, `json`).        |
| `-h, --help`    | Exibe a ajuda com todos os argumentos disponíveis.                 |

---

## Fluxo da Ferramenta

1. **Mapeamento**

   - A ferramenta inicia na URL base fornecida e coleta links internos até atingir a profundidade máxima configurada.

2. **Coleta de Formulários**

   - Durante o mapeamento, identifica formulários HTML em cada página e registra os campos encontrados.

3. **Geração e Mutação de Payloads**

   - Para cada categoria (SQLi, XSS, CMDi), são geradas variações de payloads para aumentar as chances de detecção.

4. **Testes Automatizados**

   - Os payloads são enviados aos formulários coletados e as respostas do servidor são analisadas em busca de sinais de vulnerabilidades.

5. **Relatórios**

   - Gera arquivos `.json` e/ou `.html`, dependendo dos formatos especificados, com detalhes sobre os testes realizados e possíveis falhas encontradas.

---

## Exemplos de Uso

### Executar auditoria com profundidade padrão:

```bash
python SecAuditor.py -u http://localhost:8080
```

### Executar auditoria com profundidade maior e relatórios em JSON:

```bash
python SecAuditor.py -u http://localhost:8080 -d 5 -f json
```

### Executar auditoria utilizando um proxy:

```bash
python SecAuditor.py -u http://localhost:8080 --use-proxy
```

### Exibir ajuda:

```bash
python SecAuditor.py -h
```

---

## Formato JSON

Um arquivo `.json` contendo informações detalhadas sobre URLs visitadas, formulários encontrados e resultados dos testes.

**Exemplo:**

```json
{
  "form_index": 1,
  "action": "http://localhost/login",
  "payload": "' OR 1=1 --",
  "categoria": "SQLi",
  "status_code": 200,
  "suspeita": true,
  "indicacao": "Possível SQL Injection"
}
```

---

## Formato HTML

Um arquivo `.html` com um resumo visual dos resultados da auditoria, exibindo:

- URLs visitadas
- Formulários coletados
- Resultados dos testes
- Possíveis vulnerabilidades

---

