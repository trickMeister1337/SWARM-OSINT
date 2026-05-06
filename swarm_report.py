#!/usr/bin/env python3
"""
swarm_report.py — Gerador de relatório SWARM
Uso: python3 swarm_report.py [outdir]
     Ou chamado automaticamente pelo swarm.sh via variáveis de ambiente.
"""
import json, os, html, re
from datetime import datetime, timezone

# ── Tabela CWE → CVSS sintético (baseado em médias históricas NVD) ──
# Usada como fallback para alertas ZAP que não trazem CVE nas referências
CWE_CVSS_TABLE = {
    # Injeção / execução
    "89":  {"cvss": 9.8, "sev": "CRITICAL", "name": "SQL Injection"},
    "78":  {"cvss": 9.8, "sev": "CRITICAL", "name": "OS Command Injection"},
    "77":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Command Injection"},
    "94":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Code Injection"},
    "502": {"cvss": 9.8, "sev": "CRITICAL", "name": "Deserialization of Untrusted Data"},
    "611": {"cvss": 9.1, "sev": "CRITICAL", "name": "XXE"},
    "918": {"cvss": 9.8, "sev": "CRITICAL", "name": "SSRF"},
    # Autenticação / controle de acesso
    "287": {"cvss": 9.1, "sev": "CRITICAL", "name": "Improper Authentication"},
    "306": {"cvss": 9.1, "sev": "CRITICAL", "name": "Missing Authentication"},
    "284": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Access Control"},
    "285": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Authorization"},
    "862": {"cvss": 8.1, "sev": "HIGH",     "name": "Missing Authorization"},
    "863": {"cvss": 8.1, "sev": "HIGH",     "name": "Incorrect Authorization"},
    "269": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Privilege Management"},
    # Exposição de dados
    "22":  {"cvss": 7.5, "sev": "HIGH",     "name": "Path Traversal"},
    "23":  {"cvss": 7.5, "sev": "HIGH",     "name": "Relative Path Traversal"},
    "200": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Information Disclosure"},
    "312": {"cvss": 5.5, "sev": "MEDIUM",   "name": "Cleartext Storage of Sensitive Info"},
    "319": {"cvss": 5.9, "sev": "MEDIUM",   "name": "Cleartext Transmission"},
    "359": {"cvss": 6.5, "sev": "MEDIUM",   "name": "Privacy Violation"},
    # XSS / client-side
    "79":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Cross-Site Scripting (XSS)"},
    "80":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Basic XSS"},
    "116": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Improper Encoding/Escaping"},
    "1021":{"cvss": 4.7, "sev": "MEDIUM",   "name": "Clickjacking"},
    # CSRF / sessão
    "352": {"cvss": 8.8, "sev": "HIGH",     "name": "Cross-Site Request Forgery"},
    "384": {"cvss": 7.1, "sev": "HIGH",     "name": "Session Fixation"},
    "613": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Insufficient Session Expiration"},
    # Criptografia / TLS
    "326": {"cvss": 7.5, "sev": "HIGH",     "name": "Inadequate Encryption Strength"},
    "327": {"cvss": 7.5, "sev": "HIGH",     "name": "Broken Crypto Algorithm"},
    "330": {"cvss": 7.5, "sev": "HIGH",     "name": "Insufficient Random Values"},
    "295": {"cvss": 7.4, "sev": "HIGH",     "name": "Improper Certificate Validation"},
    # Configuração / exposição
    "16":  {"cvss": 5.3, "sev": "MEDIUM",   "name": "Configuration"},
    "693": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Missing Security Header"},
    "1004":{"cvss": 4.0, "sev": "MEDIUM",   "name": "Cookie Without HttpOnly"},
    "1395":{"cvss": 6.1, "sev": "MEDIUM",   "name": "Vulnerable JavaScript Library"},
    "404": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Improper Resource Shutdown"},
    "497": {"cvss": 4.3, "sev": "MEDIUM",   "name": "Exposure of System Data"},
    "525": {"cvss": 3.7, "sev": "LOW",      "name": "Browser Caching Sensitive Info"},
}

def cwe_enrich(cweid_str):
    """Dado CWE-89 ou 89, retorna dict com cvss/sev/name ou None."""
    if not cweid_str: return None
    cwe_num = re.sub(r"[^0-9]", "", str(cweid_str))
    return CWE_CVSS_TABLE.get(cwe_num)

# ── Mapa de impacto prático por CWE (linguagem para tech lead) ──
IMPACT_MAP = {
    "89":  "Um atacante pode ler, modificar ou apagar dados do banco de dados, incluindo dados de usuários e transações.",
    "78":  "Um atacante pode executar comandos arbitrários no servidor, comprometendo toda a infraestrutura.",
    "79":  "Scripts maliciosos podem ser executados no navegador de usuários, roubando sessões e credenciais.",
    "352": "Um atacante pode forçar usuários autenticados a executar ações não autorizadas (ex: transferências, alteração de dados).",
    "22":  "Um atacante pode acessar arquivos arbitrários do servidor, incluindo configurações e chaves privadas.",
    "287": "Acesso não autorizado à aplicação, permitindo personificar qualquer usuário incluindo administradores.",
    "306": "Endpoints críticos acessíveis sem autenticação, expondo dados e funcionalidades a qualquer pessoa.",
    "284": "Usuários podem acessar recursos ou dados de outros usuários (IDOR, escalada de privilégios).",
    "918": "O servidor pode ser usado como proxy para acessar serviços internos protegidos (AWS metadata, bancos de dados).",
    "611": "Processamento de XML externo pode vazar arquivos do servidor ou causar denial of service.",
    "502": "Deserialização de dados não confiáveis pode resultar em execução remota de código.",
    "326": "Comunicações criptografadas podem ser interceptadas e decifradas por atacantes na rede.",
    "327": "Algoritmos criptográficos fracos podem ser quebrados, expondo dados sensíveis.",
    "295": "Comunicações TLS podem ser interceptadas por ataques man-in-the-middle.",
    "1021":"Usuários podem ser induzidos a clicar em elementos invisíveis sobrepostos (clickjacking).",
    "319": "Dados transmitidos em texto claro podem ser interceptados por qualquer observador na rede.",
    "200": "Informações sobre tecnologias, versões ou estrutura interna expostas a atacantes.",
    "693": "Ausência de cabeçalhos de segurança deixa o browser do usuário sem proteções básicas contra XSS e injeção.",
    "1004":"Cookies de sessão acessíveis via JavaScript podem ser roubados por scripts maliciosos (XSS).",
    "1395":"Biblioteca JavaScript com vulnerabilidade conhecida e exploit público disponível.",
    "312": "Dados sensíveis armazenados sem criptografia podem ser acessados diretamente no banco de dados.",
    "384": "Um atacante pode fixar o identificador de sessão de um usuário e assumir sua conta após login.",
}

# ── Mapa de remediação específica por CWE ────────────────────
REMEDIATION_MAP = {
    "89":  "Use prepared statements (parametrized queries) em todas as queries SQL. Nunca concatene dados do usuário diretamente.",
    "79":  "Escape de output em contexto HTML/JS. Implemente Content-Security-Policy. Use bibliotecas como DOMPurify.",
    "352": "Implemente tokens CSRF (ex: SameSite=Strict em cookies, token por formulário). Frameworks como Spring, Django e Rails têm suporte nativo.",
    "22":  "Valide e normalize caminhos de arquivo. Use allowlist de diretórios permitidos. Evite concatenar input do usuário em caminhos.",
    "287": "Implemente autenticação forte com MFA. Use sessões seguras com expiração adequada.",
    "306": "Adicione autenticação a todos os endpoints. Use middleware de auth centralizado.",
    "284": "Valide no servidor que o usuário tem permissão para acessar o recurso solicitado. Não confie apenas no ID da URL.",
    "918": "Valide e filtre URLs de destino em qualquer funcionalidade de proxy/redirect. Use allowlist de hosts permitidos.",
    "693": "Configure cabeçalhos: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security.",
    "1004":"Adicione flag HttpOnly em todos os cookies de sessão. Use também Secure e SameSite=Strict.",
    "1395":"Atualize a biblioteca para a versão mais recente. Verifique release notes para breaking changes.",
    "326": "Use TLS 1.2+ com cipher suites modernas. Desabilite SSLv3, TLS 1.0, TLS 1.1 e RC4.",
    "319": "Force HTTPS em toda a aplicação. Implemente HSTS. Redirecione HTTP para HTTPS.",
    "352": "Tokens CSRF em formulários e headers X-CSRF-Token para APIs. Verifique Origin/Referer como camada adicional.",
    "312": "Criptografe dados sensíveis em repouso. Use bcrypt/Argon2 para senhas. Nunca armazene em texto claro.",
}

def cvss_to_sev(score):
    """Converte score CVSS para severidade pelo padrão NVD."""
    if score is None: return None
    score = float(score)
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"

OUTDIR          = os.environ.get('OUTDIR','scan_output')
TARGET          = os.environ.get('TARGET','https://example.com')
DOMAIN          = os.environ.get('DOMAIN','example.com')
OPEN_PORTS      = os.environ.get('OPEN_PORTS','N/A')
ACTIVE_COUNT    = os.environ.get('ACTIVE_COUNT','0')
SUB_COUNT       = os.environ.get('SUB_COUNT','0')
OPENAPI_FOUND   = os.environ.get('OPENAPI_FOUND','0') == '1'
TLS_ISSUES      = int(os.environ.get('TLS_ISSUES','0'))
CONFIRMED_COUNT = int(os.environ.get('CONFIRMED_COUNT','0'))
SCAN_START_TS   = int(os.environ.get('SCAN_START_TS','0'))

# Carregar tempos por fase
phase_times = {}
_ptf = os.path.join(OUTDIR,'raw','.phase_times')
if os.path.exists(_ptf):
    try:
        for _line in open(_ptf):
            _parts = _line.strip().split(':')
            if len(_parts) >= 5 and _parts[1] == 'end':
                phase_times[_parts[0]] = int(_parts[4])
    except: pass
JS_SECRETS      = int(os.environ.get('JS_SECRETS','0'))
JS_ENDPOINTS    = int(os.environ.get('JS_ENDPOINTS','0'))
JS_FRAMEWORKS   = int(os.environ.get('JS_FRAMEWORKS','0'))
JS_FILES        = int(os.environ.get('JS_FILES','0'))
KATANA_URLS      = int(os.environ.get('KATANA_URLS','0'))
SMUGGLER_FOUND   = int(os.environ.get('SMUGGLER_FOUND','0'))
FFUF_FOUND       = int(os.environ.get('FFUF_FOUND','0'))
TRUFFLEHOG_FOUND = int(os.environ.get('TRUFFLEHOG_FOUND','0'))
WAF_DETECTED    = os.environ.get('WAF_DETECTED','') == '1'
WAF_NAME        = os.environ.get('WAF_NAME','')
EMAIL_ISSUES    = int(os.environ.get('EMAIL_ISSUES','0'))
errors = []

# Nuclei
findings = []
nuclei_file = os.path.join(OUTDIR,"raw","nuclei.json")
if os.path.exists(nuclei_file) and os.path.getsize(nuclei_file) > 0:
    with open(nuclei_file,"r",encoding="utf-8") as f:
        for ln, line in enumerate(f,1):
            line = line.strip()
            if not line: continue
            try:
                data = json.loads(line)
                info = data.get("info",{})
                sev  = info.get("severity","info").lower()
                cl   = info.get("classification",{}) or {}
                cves = cl.get("cve-id",[]) or []
                # Evidência: montar a partir de request/response/matcher do nuclei
                ev_parts = []
                if data.get("request"): ev_parts.append("REQUEST:\n" + str(data["request"]))
                if data.get("response"): ev_parts.append("RESPONSE:\n" + str(data["response"]))
                if data.get("extracted-results"): ev_parts.append("EXTRACTED: " + str(data["extracted-results"]))
                if data.get("curl-command"): ev_parts.append("CURL:\n" + str(data["curl-command"]))
                ev = "\n\n".join(ev_parts)  # sem truncagem — evidência completa
                meta = data.get("meta",{}) or {}
                findings.append({"source":"Nuclei","name":info.get("name","Vuln"),
                    "severity":sev,"description":(info.get("description","N/A") or "N/A"),
                    "cve":", ".join(cves) if cves else "N/A","url":data.get("matched-at",TARGET),
                    "remediation":info.get("remediation","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":str(meta.get("username","") or meta.get("param","") or ""),
                    "attack":str(meta.get("password","") or ""),
                    "other":data.get("template-id","") or ""})
            except json.JSONDecodeError as e: errors.append(f"Nuclei L{ln}: {e}")
            except Exception as e: errors.append(f"Nuclei L{ln}: {type(e).__name__}: {e}")

# ZAP — com deduplicação de alertas repetidos e filtro de confiança
zap_findings = []
zap_low_groups = {}  # Low/Info: tabela compacta
zap_dedup      = {}  # Critical/High/Medium: card único por tipo
# Carregar request/response do XML ZAP para evidência completa
_zap_xml_evidence = {}  # name -> {request, response}
_zap_xml_path = os.path.join(OUTDIR,"raw","zap_evidencias.xml")
if os.path.exists(_zap_xml_path):
    try:
        import xml.etree.ElementTree as ET
        _xtree = ET.parse(_zap_xml_path)
        for _xalert in _xtree.findall(".//alertitem"):
            _xname = (_xalert.findtext("alert") or "").strip()
            if _xname and _xname not in _zap_xml_evidence:
                _xreq  = (_xalert.findtext("requestheader") or "").strip()
                _xreqb = (_xalert.findtext("requestbody") or "").strip()
                _xres  = (_xalert.findtext("responseheader") or "").strip()
                _xresb = (_xalert.findtext("responsebody") or "").strip()
                _xfull_req = _xreq + ("\n\n" + _xreqb if _xreqb else "")
                _xfull_res = _xres + ("\n\n" + _xresb if _xresb else "")  # evidência completa sem truncagem
                _zap_xml_evidence[_xname] = {
                    "request":  _xfull_req,
                    "response": _xfull_res
                }
    except Exception as _xe: errors.append(f"ZAP XML: {_xe}")

zap_file = os.path.join(OUTDIR,"raw","zap_alerts.json")
if os.path.exists(zap_file) and os.path.getsize(zap_file) > 0:
    try:
        zap_data = json.load(open(zap_file,"r",encoding="utf-8"))
        rmap = {"high":"high","medium":"medium","low":"low","informational":"info"}
        SKIP_CONFIDENCE = {"false positive"}

        # ── Padrões de URLs geradas pelo spider que não representam recursos reais ──
        # Redirects de autenticação (Jenkins, Jira, Confluence, etc.)
        # e URLs com parâmetros de redirect injetados pelo scanner
        URL_SKIP_PATTERNS = [
            r'/securityRealm/',          # Jenkins auth redirect
            r'moLogin\?from=',           # Jenkins login redirect
            r'j_spring_security',        # Spring Security login
            r'login\?from=%2F',          # Generic auth redirect
            r'login\?next=%2F',          # Django/Flask auth redirect
            r'signin\?returnUrl=',       # Generic signin redirect
            r'auth\?redirect=',          # Generic auth redirect
            r'\?from=%2F',              # ZAP-injected redirect param
            r'\?from=%2Fsitemap',        # sitemap redirect artifact
            r'\?from=%2Fstatic',         # static asset redirect artifact
            r'/j_acegi_security',        # Legacy Spring Security
            r'oauth/authorize\?',        # OAuth artifacts
            r'saml/login\?',             # SAML redirect artifacts
        ]

        def url_is_real(url):
            """Retorna False se a URL é claramente um artefato de redirect/scanner."""
            if not url:
                return True
            for pattern in URL_SKIP_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    return False
            return True

        for i,a in enumerate(zap_data.get("alerts",[])):
            try:
                sev_orig = rmap.get(a.get("risk","info").lower(),"info")
                conf = a.get("confidence","").lower()
                if conf in SKIP_CONFIDENCE:
                    continue

                # ── Filtrar URLs que não representam recursos reais ──────────
                alert_url = a.get("url","")
                if not url_is_real(alert_url):
                    errors.append(f"ZAP URL filtrada (redirect artefato): {alert_url[:80]}")
                    continue
                # Reclassificar severidade via CVSS do CWE (Opção C — tabela sintética)
                _cweid = str(a.get("cweid","") or "")
                _cwe_data = cwe_enrich(_cweid)
                sev_reclassified = False
                if _cwe_data:
                    sev_from_cvss = cvss_to_sev(_cwe_data["cvss"])
                    # v3: limitar reclassificação a no máximo +1 nível de severidade
                    # evita que alertas Low/Info saltem para Critical por CWE
                    SEV_LADDER = ["info","low","medium","high","critical"]
                    orig_idx = SEV_LADDER.index(sev_orig) if sev_orig in SEV_LADDER else 0
                    new_idx  = SEV_LADDER.index(sev_from_cvss) if sev_from_cvss in SEV_LADDER else orig_idx
                    capped_idx = min(new_idx, orig_idx + 1)  # máximo +1 nível
                    sev_capped = SEV_LADDER[capped_idx]
                    if sev_capped != sev_orig:
                        sev = sev_capped
                        sev_reclassified = True
                    else:
                        sev = sev_orig
                else:
                    sev = sev_orig
                # Evidência completa: campos JSON + request/response do XML ZAP
                ev_parts_zap = []
                _alert_name = a.get("name","")
                _xml_ev = _zap_xml_evidence.get(_alert_name, {})
                if a.get("param",""):      ev_parts_zap.append(f"Parâmetro: {a['param']}")
                if a.get("attack",""):     ev_parts_zap.append(f"Vetor de Ataque:\n{a['attack']}")
                if a.get("evidence",""):   ev_parts_zap.append(f"Evidência:\n{a['evidence']}")
                if _xml_ev.get("request"): ev_parts_zap.append(f"--- REQUISIÇÃO HTTP ---\n{_xml_ev['request']}")
                if _xml_ev.get("response"):ev_parts_zap.append(f"--- RESPOSTA HTTP ---\n{_xml_ev['response']}")
                if a.get("other",""):      ev_parts_zap.append(f"Detalhe adicional:\n{a['other']}")
                ev = "\n\n".join(ev_parts_zap)  # sem truncagem — evidência completa
                # Extrair CVE do campo reference; fallback para CWE
                _refs = a.get("reference","") or ""
                _cves = re.findall(r"CVE-\d{4}-\d{4,7}", _refs, re.IGNORECASE)
                _cve_str = ", ".join(sorted(set(c.upper() for c in _cves))) if _cves \
                    else f"CWE-{a.get('cweid','N/A')}"
                f_entry = {"source":"OWASP ZAP","name":a.get("name","Alerta"),
                    "severity":sev,
                    "severity_orig":sev_orig,
                    "severity_reclassified":sev_reclassified,
                    "cvss_synthetic":_cwe_data["cvss"] if _cwe_data else None,
                    "description":(a.get("description","N/A") or "N/A"),
                    "cve": f"{_cve_str} | Conf: {a.get('confidence','?')}",
                    "url":a.get("url",TARGET),
                    "remediation":a.get("solution","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":(a.get("param","") or ""),
                    "attack":(a.get("attack","") or ""),
                    "other":(a.get("other","") or "")}
                # Estratégia de deduplicação por severidade:
                # Critical/High → card único por nome (melhor evidência + lista de URLs)
                # Medium        → card único por nome (melhor evidência + lista de URLs)
                # Low/Info      → tabela compacta agrupada
                name = a.get("name","Alerta")
                url  = a.get("url","")
                if sev in ("low","info"):
                    if name not in zap_low_groups:
                        zap_low_groups[name] = {"count":0,"urls":[],"finding":f_entry,
                            "cve": _cve_str, "conf":a.get("confidence","?"),
                            "sev": sev}
                    zap_low_groups[name]["count"] += 1
                    if url and url not in zap_low_groups[name]["urls"]:
                        zap_low_groups[name]["urls"].append(url)
                else:
                    # Deduplicar Medium/High/Critical por nome
                    # Manter o finding com maior evidência; acumular URLs distintas
                    if name not in zap_dedup:
                        zap_dedup[name] = {"finding": f_entry, "urls": [], "count": 0, "sev": sev}
                    # Promover para maior severidade encontrada
                    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                    if sev_order.get(sev,5) < sev_order.get(zap_dedup[name]["sev"],5):
                        zap_dedup[name]["finding"] = f_entry
                        zap_dedup[name]["sev"] = sev
                    # Preferir finding com evidência real
                    if f_entry.get("evidence") and not zap_dedup[name]["finding"].get("evidence"):
                        zap_dedup[name]["finding"] = f_entry
                    zap_dedup[name]["count"] += 1
                    if url and url not in zap_dedup[name]["urls"]:
                        zap_dedup[name]["urls"].append(url)
            except Exception as e: errors.append(f"ZAP alerta {i}: {e}")
    except json.JSONDecodeError as e: errors.append(f"ZAP JSON malformado: {e}")
    except Exception as e: errors.append(f"ZAP: {e}")

# Converter zap_dedup em zap_findings, injetando lista de URLs afetadas
for name, grp in zap_dedup.items():
    f = dict(grp["finding"])  # cópia
    affected = grp["urls"]
    f["severity"] = grp["sev"]  # severidade mais alta encontrada
    f["affected_count"] = grp["count"]
    f["affected_urls"] = affected
    # Se mais de uma URL, adicionar lista às outras informações do card
    if len(affected) > 1:
        extra = f"\n\n[{len(affected)} URLs afetadas]\n" + "\n".join(f"  • {u}" for u in affected[:20])
        if len(affected) > 20:
            extra += f"\n  ... e mais {len(affected)-20} URL(s)"
        f["other"] = (f.get("other","") + extra).strip()
    zap_findings.append(f)

# httpx / nmap
httpx_lines = []
hf = os.path.join(OUTDIR,"raw","httpx_results.txt")
if os.path.exists(hf):
    try: httpx_lines = [l.strip() for l in open(hf) if l.strip()]
    except Exception as e: errors.append(f"httpx: {e}")

nmap_lines = []
nf = os.path.join(OUTDIR,"raw","nmap.txt")
if os.path.exists(nf):
    try: nmap_lines = [l.strip() for l in open(nf) if "open" in l and "/tcp" in l]
    except Exception as e: errors.append(f"nmap: {e}")

# ── testssl ───────────────────────────────────────────────────
tls_findings = []
tf = os.path.join(OUTDIR,"raw","testssl.json")
if os.path.exists(tf) and os.path.getsize(tf) > 0:
    try:
        tdata = json.load(open(tf,"r",encoding="utf-8"))
        findings_raw = tdata if isinstance(tdata,list) else \
            tdata.get("scanResult",[{}])[0].get("findings",[])
        SEV_MAP = {"CRITICAL":"critical","HIGH":"high","WARN":"medium","LOW":"low","OK":"info","INFO":"info"}
        for item in findings_raw:
            sev_raw = item.get("severity","INFO")
            sev = SEV_MAP.get(sev_raw.upper(),"info")
            if sev_raw.upper() in ("CRITICAL","HIGH","WARN","LOW"):
                tls_findings.append({
                    "id":   item.get("id",""),
                    "sev":  sev,
                    "sev_raw": sev_raw,
                    "finding": item.get("finding",""),
                    "cve":  item.get("cve",""),
                })
    except Exception as e: errors.append(f"testssl: {e}")

# ── exploit confirmations ─────────────────────────────────────
confirmations = []
cf = os.path.join(OUTDIR,"raw","exploit_confirmations.json")
if os.path.exists(cf) and os.path.getsize(cf) > 0:
    try: confirmations = json.load(open(cf,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"confirmations: {e}")

# ── Índice de confirmações por URL+template para cross-reference ──
# Permite que render_finding() mostre badge "CONFIRMADO" nos achados validados
_conf_index = {}          # url (normalizada) → list[dict]
_conf_template_index = {} # template_id       → dict (melhor confirmação)
for _c in (confirmations if isinstance(confirmations, list) else []):
    if not isinstance(_c, dict): continue
    _curl = (_c.get("url") or "").rstrip("/").lower()
    if _curl not in _conf_index: _conf_index[_curl] = []
    _conf_index[_curl].append(_c)
    _tid = (_c.get("template_id") or "").lower()
    if _tid:
        _prev = _conf_template_index.get(_tid)
        if not _prev or (_c.get("confirmed") and not _prev.get("confirmed")):
            _conf_template_index[_tid] = _c

def _get_confirmation(finding):
    """Retorna o melhor match de confirmação para um finding, ou None."""
    # Por template_id (nuclei armazena template-id em 'other')
    _tid = (finding.get("other") or "").lower()
    if _tid and _tid in _conf_template_index:
        return _conf_template_index[_tid]
    # Fallback: por URL
    _furl = (finding.get("url") or "").rstrip("/").lower()
    _matches = _conf_index.get(_furl, [])
    if _matches:
        return sorted(_matches, key=lambda x: (not x.get("confirmed"), -x.get("confidence",0)))[0]
    return None

# ── Normalização defensiva das confirmações (poc_validator.py) ──
# Garante que todos os campos consumidos pelo render existam, mesmo quando
# o validador emite estruturas parciais ou usa nomes alternativos.
def _norm_sev(v, default="info"):
    if not v: return default
    s = str(v).strip().lower()
    # mapeamentos comuns
    if s in ("crit","critical"): return "critical"
    if s in ("hi","high"): return "high"
    if s in ("med","medium","moderate"): return "medium"
    if s in ("lo","low"): return "low"
    if s in ("informational","information","info","none","unknown"): return "info"
    return s if s in ("critical","high","medium","low","info") else default

_normalized_conf = []
for _c in (confirmations if isinstance(confirmations, list) else []):
    if not isinstance(_c, dict):
        continue
    # severity: tenta vários campos possíveis
    _sev_raw = (_c.get("severity")
                or (_c.get("info") or {}).get("severity")
                or _c.get("sev")
                or _c.get("risk"))
    # se o validador classificou nível de confiança (confirmed-oob, etc.),
    # mapeia para severidade equivalente quando severity está ausente
    if not _sev_raw:
        _conf_lvl = str(_c.get("confidence_level","")).lower()
        if "oob" in _conf_lvl or "rce" in _conf_lvl:    _sev_raw = "critical"
        elif "reflected" in _conf_lvl or "sqli" in _conf_lvl: _sev_raw = "high"
        elif "version" in _conf_lvl:                     _sev_raw = "medium"
        elif "probable" in _conf_lvl:                    _sev_raw = "low"
        else:                                            _sev_raw = "info"
    _c["severity"] = _norm_sev(_sev_raw, "info")

    # demais campos defensivos
    _c.setdefault("confirmed", False)
    _c.setdefault("template_id", _c.get("id") or _c.get("template-id") or "—")
    _c.setdefault("url", _c.get("matched-at") or _c.get("host") or _c.get("target") or "—")
    _c.setdefault("http_status", str(_c.get("status_code") or _c.get("status") or "—"))
    _c.setdefault("confidence", _c.get("confidence_score") or 0)
    try: _c["confidence"] = int(_c["confidence"])
    except Exception: _c["confidence"] = 0
    _c.setdefault("vuln_type", _c.get("type") or _c.get("confidence_level") or "")
    _c.setdefault("poc_note", _c.get("note") or _c.get("reason") or "—")
    _c.setdefault("response_headers", _c.get("headers") or "")
    _c.setdefault("response_body", _c.get("body") or _c.get("evidence") or "")
    _c.setdefault("curl_reproducible", _c.get("curl") or "")
    _c.setdefault("curl_command", _c.get("curl") or "")
    _normalized_conf.append(_c)
confirmations = _normalized_conf

# ── WAF & Email Security ───────────────────────────────────
email_security = {}
_esf = os.path.join(OUTDIR,'raw','email_security.json')
if os.path.exists(_esf):
    try: email_security = json.load(open(_esf))
    except Exception as e: errors.append(f'email_security: {e}')

# ── Scan metadata (comportamento + evasão) ───────────────────
scan_meta = {}
_smf = os.path.join(OUTDIR,'raw','scan_metadata.json')
if os.path.exists(_smf):
    try: scan_meta = json.load(open(_smf))
    except Exception as e: errors.append(f'scan_metadata: {e}')

# ── Security headers data ─────────────────────────────────────
security_headers_data = []
_shf = os.path.join(OUTDIR,'raw','security_headers.json')
if os.path.exists(_shf):
    try: security_headers_data = json.load(open(_shf))
    except Exception as e: errors.append(f'security_headers: {e}')

# ── JS Analysis ──────────────────────────────────────────────
js_analysis = {}
js_file = os.path.join(OUTDIR,"raw","js_analysis.json")
if os.path.exists(js_file) and os.path.getsize(js_file) > 0:
    try: js_analysis = json.load(open(js_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"js_analysis: {e}")
js_secrets    = js_analysis.get("secrets",[])
js_endpoints  = js_analysis.get("endpoints",[])
js_frameworks = js_analysis.get("frameworks",[])
js_files_list = js_analysis.get("js_files",[])
js_probes     = js_analysis.get("endpoint_probes",[])
js_comments   = js_analysis.get("sensitive_comments",[])

# ── CVE enrichment (NVD + EPSS) ──────────────────────────────
cve_enrichment = {}
cve_db_file = os.path.join(OUTDIR,"raw","cve_enrichment.json")
if os.path.exists(cve_db_file) and os.path.getsize(cve_db_file) > 0:
    try: cve_enrichment = json.load(open(cve_db_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"cve_enrichment: {e}")

# KEV matches — CVEs encontrados no catálogo CISA
kev_matches = {}
_kev_f = os.path.join(OUTDIR,"raw","kev_matches.json")
if os.path.exists(_kev_f):
    try: kev_matches = json.load(open(_kev_f,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"kev_matches: {e}")
kev_count = len(kev_matches)

# Reclassificar achados Nuclei usando CVSS real do NVD quando disponível
for f in findings:
    cve_field = f.get('cve','')
    cve_ids_f = re.findall(r'CVE-\d{4}-\d{4,7}', cve_field, re.IGNORECASE)
    best_cvss = None
    for cid in [c.upper() for c in cve_ids_f]:
        ev = cve_enrichment.get(cid,{})
        cvss_val = ev.get('cvss_v3') or ev.get('cvss_v2')
        if cvss_val and (best_cvss is None or float(cvss_val) > best_cvss):
            best_cvss = float(cvss_val)
    if best_cvss is not None:
        new_sev = cvss_to_sev(best_cvss)
        if new_sev and new_sev != f['severity']:
            f['severity_orig'] = f['severity']
            f['severity'] = new_sev
            f['severity_reclassified'] = True
            f['cvss_real'] = best_cvss
        else:
            f.setdefault('severity_orig', f['severity'])
            f.setdefault('severity_reclassified', False)
    else:
        f.setdefault('severity_orig', f['severity'])
        f.setdefault('severity_reclassified', False)


# Stats — contagem de CARDS únicos por severidade (padrão relatórios profissionais)
# Cada tipo de vulnerabilidade = 1, independente de quantas URLs afeta
# Normalização defensiva: garante 'severity' em todo finding antes do sort/render
def _ensure_sev(_f):
    if not isinstance(_f, dict): return {"severity":"info","name":"—","source":"?"}
    _s = _f.get("severity") or (_f.get("info") or {}).get("severity") or "info"
    _f["severity"] = _norm_sev(_s, "info")
    _f.setdefault("name", _f.get("template-id") or _f.get("id") or "—")
    _f.setdefault("url",  _f.get("matched-at") or _f.get("host") or "—")
    return _f
all_f = sorted(
    [_ensure_sev(x) for x in (findings + zap_findings)],
    key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"],5)
)
stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
for f in all_f:
    if f["severity"] in stats: stats[f["severity"]] += 1
# v3: contar confirmados para exibir no summary
n_confirmed_findings = sum(1 for c in confirmations if c.get("confirmed"))
# Low/Info: cada grupo = 1 card (tipo único)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in stats: stats[sev] += 1
total = sum(stats.values())

# Ocorrências reais — usadas apenas para o risk score (reflete severidade total do ambiente)
occurrences = dict(stats)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)
for grp in zap_dedup.values():
    sev = grp["sev"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)

# ── Risk score: KEV > EPSS > CVSS (metodologia 2026) ───────────
# v3: achados confirmados pelo poc_validator valem o dobro na base de risco
# Achados não-confirmados são penalizados com fator 0.5
_confirmed_urls = {(_c.get("url") or "").rstrip("/").lower()
                   for _c in confirmations if _c.get("confirmed")}

def _weighted_count(sev_filter):
    """Conta ocorrências ponderadas pela confirmação do poc_validator."""
    total = 0
    for _f in all_f:
        if _f.get("severity") not in sev_filter: continue
        _fu = (_f.get("url") or "").rstrip("/").lower()
        if _fu in _confirmed_urls:
            total += 2   # confirmado = peso duplo
        else:
            total += 1   # não confirmado = peso normal (era fonte de inflação)
    return total

base_risk = (
    _weighted_count({"critical"}) * 10 +
    _weighted_count({"high"})     *  5 +
    _weighted_count({"medium"})   *  2 +
    occurrences.get("low", 0)
)

# Camada 1 — KEV: exploração ativa confirmada (peso máximo)
# Um CVE no KEV é automaticamente urgente independente do CVSS
kev_bonus = 0
kev_count = sum(1 for ev in cve_enrichment.values() if ev.get("in_kev"))
if kev_count > 0:
    kev_bonus = min(kev_count * 25, 50)  # +25 por CVE no KEV, cap 50

# Camada 2 — EPSS: probabilidade de exploração nos próximos 30 dias
epss_bonus = 0
for ev in cve_enrichment.values():
    epss = ev.get("epss_score") or 0
    if epss >= 0.5:    epss_bonus += 15   # exploit muito provável (>50%)
    elif epss >= 0.1:  epss_bonus += 7    # exploit provável (>10%)
    elif epss >= 0.01: epss_bonus += 2    # exploit possível (>1%)
# Bônus JS: secrets e frameworks vulneráveis agravam o risco
HIGH_JS_TYPES = {"AWS Access Key","AWS Secret","Private Key","Stripe Live Key","GitHub Token","GitLab PAT","OpenAI Key","Anthropic Key","Hardcoded Password","DB Connection String"}
js_high   = [s for s in js_secrets if s.get("type","") in HIGH_JS_TYPES]
js_medium = [s for s in js_secrets if s.get("type","") not in HIGH_JS_TYPES]
js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
js_bonus = min(len(js_high)*15 + len(js_medium)*5 + len(js_vuln_fw)*8, 30)
risk = min(base_risk + kev_bonus + epss_bonus + js_bonus, 100)
# Classificação baseada no risk score (KEV+EPSS+CVSS) — não apenas contagem
# Faixas: 70-100=CRÍTICO, 40-69=ALTO, 15-39=MÉDIO, 0-14=BAIXO
if risk >= 70:
    stxt, scol = "CRÍTICO — Ação Imediata",     "#7a2e2e"
elif risk >= 40:
    stxt, scol = "ALTO — Atenção Urgente",       "#b34e4e"
elif risk >= 15:
    stxt, scol = "MÉDIO — Correção Planejada",   "#d4833a"
else:
    stxt, scol = "BAIXO — Monitoramento",        "#4a7c8c"
rdate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
import time as _time
duration_secs = int(_time.time()) - SCAN_START_TS if SCAN_START_TS else 0
duration_str = f"{duration_secs//3600}h {(duration_secs%3600)//60}m {duration_secs%60}s" if duration_secs > 0 else "N/A"

def badge(sev):
    labels = {"critical":"CRÍTICO","high":"ALTO","medium":"MÉDIO","low":"BAIXO","info":"INFO"}
    c={"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#6e8f72"}.get(sev,"#999")
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{labels.get(sev, labels.get(sev.lower(), sev.upper()))}</span>'

def trows(items,empty="Sem resultados"):
    if not items: return f'<tr><td style="color:#999;font-style:italic">{empty}</td></tr>'
    return "".join(f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(i)}</td></tr>' for i in items[:50])

def render_finding(f):
    # Enriquecer CVE com dados NVD/EPSS se disponível
    cve_val = f.get('cve','N/A')
    enrich_rows = ''
    # Extrair CVE IDs do campo cve
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', cve_val, re.IGNORECASE)
    for cve_id in [c.upper() for c in cve_ids]:
        ev = cve_enrichment.get(cve_id, {})
        if ev:
            cvss = ev.get('cvss_v3') or ev.get('cvss_v2')
            epss = ev.get('epss_score')
            epss_pct = ev.get('epss_percentile')
            sev = ev.get('severity','')
            desc_nvd = ev.get('description','')
            cvss_color = '#7a2e2e' if cvss and cvss>=9 else '#b34e4e' if cvss and cvss>=7 else '#d4833a' if cvss and cvss>=4 else '#27ae60'
            epss_color = '#7a2e2e' if epss and epss>=0.5 else '#d4833a' if epss and epss>=0.1 else '#27ae60'
            enrich_rows += f'<tr><th>{html.escape(cve_id)}</th><td>'
            _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
            sev_pt = _SEV_PT.get(str(sev).upper(), sev)
            # KEV badge — máxima prioridade, exibido antes de CVSS/EPSS
            in_kev = ev.get("in_kev", False)
            kev_info = ev.get("kev", {})
            if in_kev:
                kev_due = kev_info.get("due_date","")
                kev_added = kev_info.get("date_added","")
                kev_prod = f"{kev_info.get('vendor','')} {kev_info.get('product','')}".strip()
                enrich_rows += (f'<span style="background:#7a0000;color:white;padding:2px 10px;'
                    f'border-radius:4px;font-size:12px;font-weight:bold;'
                    f'border:2px solid #ff4444;letter-spacing:.3px">'
                    f'🔴 EXPLORAÇÃO ATIVA — CISA KEV</span> ')
                if kev_due: enrich_rows += f'<span style="background:#b34e4e;color:white;padding:1px 6px;border-radius:3px;font-size:11px">Prazo CISA: {html.escape(kev_due)}</span> '
                if kev_prod: enrich_rows += f'<br><small style="color:#7a0000;font-weight:bold">Adicionado ao KEV em {html.escape(kev_added)} — {html.escape(kev_prod)}</small> '
            if cvss: enrich_rows += f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS {cvss} {html.escape(sev_pt)}</span> '
            if epss is not None: enrich_rows += f'<span style="background:{epss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px">EPSS {epss:.4f} ({epss_pct*100:.1f}° percentil)</span> '
            # Link direto para advisory NVD
            enrich_rows += (f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(cve_id)}" '
                f'target="_blank" style="font-size:11px;color:#388bfd;margin-left:6px">'
                f'Ver no NVD ↗</a> ')
            if desc_nvd: enrich_rows += f'<br><small style="color:#555">{html.escape(desc_nvd)}</small>'
            enrich_rows += '</td></tr>'
    # Fallback CWE sintético — quando não há CVE NVD disponível
    if not cve_ids or not enrich_rows:
        cwe_match = re.search(r'CWE-?(\d+)', cve_val, re.IGNORECASE)
        if cwe_match:
            cwe_data = cwe_enrich(cwe_match.group(1))
            if cwe_data:
                cvss = cwe_data["cvss"]
                _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
                sev_label = _SEV_PT.get(cwe_data["sev"], cwe_data["sev"])
                cwe_name = cwe_data["name"]
                cvss_color = '#7a2e2e' if cvss>=9 else '#b34e4e' if cvss>=7 else '#d4833a' if cvss>=4 else '#27ae60'
                enrich_rows += (f'<tr><th>CWE-{cwe_match.group(1)}</th><td>'
                    f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS ~{cvss} {sev_label}</span> '
                    f'<span style="background:#636e72;color:white;padding:1px 6px;border-radius:3px;font-size:11px">Estimativa baseada em CWE</span>'
                    f'<br><small style="color:#555">{html.escape(cwe_name)}</small>'
                    f'</td></tr>')
    # Badge de reclassificação — mostrar quando severidade original difere da atual
    sev_orig = f.get('severity_orig', f.get('severity',''))
    was_reclassified = f.get('severity_reclassified', False)
    reclassify_badge = ''
    if was_reclassified and sev_orig and sev_orig != f.get('severity',''):
        labels = {'critical':'CRÍTICO','high':'ALTO','medium':'MÉDIO','low':'BAIXO','info':'INFO'}
        orig_label = labels.get(sev_orig, sev_orig.upper())
        reclassify_badge = (f'<span style="background:#2d3436;color:#dfe6e9;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;margin-left:6px">'
            f'↑ Reclassificado de {orig_label} (CVE/CWE)</span>')

    rows = f"""
    <tr><th style="width:120px">CVE/CWE</th><td>{html.escape(str(f.get('cve','N/A')))}</td></tr>
    {enrich_rows}
    <tr><th>URL</th><td><code>{html.escape(f.get('url',''))}</code></td></tr>
    <tr><th>Descrição</th><td>{html.escape(f.get('description',''))}</td></tr>"""
    # Impacto prático — extrair CWE do campo cve para lookup no IMPACT_MAP
    _cwe_for_impact = re.search(r'CWE-?(\d+)', f.get("cve",""), re.IGNORECASE)
    _impact = IMPACT_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    _remediation_specific = REMEDIATION_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    if _impact:
        rows += (f'\n    <tr><th style="background:#fff3cd;color:#856404">⚠ Impacto</th>'
            f'<td style="background:#fff3cd;color:#856404;font-weight:500">{html.escape(_impact)}</td></tr>')
    if _remediation_specific:
        rows += (f'\n    <tr><th style="background:#d4edda;color:#155724">✓ Como Corrigir</th>'
            f'<td style="background:#d4edda;color:#155724">{html.escape(_remediation_specific)}</td></tr>')
    if f.get('param'):
        rows += f"\n    <tr><th>Parâmetro</th><td><code>{html.escape(f['param'])}</code></td></tr>"
    if f.get('attack'):
        rows += f"\n    <tr><th>Ataque</th><td><code>{html.escape(f['attack'])}</code></td></tr>"
    # Exibir evidência dividida em blocos legíveis
    _ev_full = f.get("evidence","")
    if _ev_full:
        _req_match  = re.search(r"--- REQUISIÇÃO HTTP ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _res_match  = re.search(r"--- RESPOSTA HTTP ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _ev_other   = re.sub(r"--- (REQUISIÇÃO|RESPOSTA) HTTP ---\n.*?(?=---|$)", "", _ev_full, flags=re.DOTALL).strip()
        if _ev_other:
            rows += f'\n    <tr><th>Evidência</th><td><div class="evidence-box">{html.escape(_ev_other)}</div></td></tr>'
        if _req_match:
            rows += f'\n    <tr><th>Requisição HTTP</th><td><div class="evidence-box">{html.escape(_req_match.group(1).strip())}</div></td></tr>'
        if _res_match:
            rows += f'\n    <tr><th>Resposta HTTP</th><td><div class="evidence-box">{html.escape(_res_match.group(1).strip())}</div></td></tr>'
    if f.get('affected_count', 0) > 1:
        n = f['affected_count']
        urls_sample = f.get('affected_urls', [])
        url_list = ''.join(f'<li><code>{html.escape(u)}</code></li>' for u in urls_sample)
        rows += (f'\n    <tr><th>URLs Afetadas</th>'
            f'<td><strong>{n} ocorrência(s)</strong> do mesmo tipo de alerta:<ul style="margin:6px 0 0;padding-left:18px">{url_list}</ul></td></tr>')
    other_val = f.get('other','')
    if other_val and '[URLs afetadas]' not in other_val:
        rows += f"\n    <tr><th>Detalhe</th><td>{html.escape(other_val)}</td></tr>"
    rows += f"\n    <tr><th>Recomendação</th><td>{html.escape(f.get('remediation',''))}</td></tr>"
    src_cls = 'source-nuclei' if f.get('source') == 'Nuclei' else 'source-zap'
    # v3: badge de confirmação ativa — cross-reference com poc_validator
    _conf_match = _get_confirmation(f)
    _conf_badge = ""
    if _conf_match:
        if _conf_match.get("confirmed"):
            _conf_pct = _conf_match.get("confidence", 0)
            _conf_badge = (f'<span style="background:#155724;color:white;padding:2px 8px;'
                           f'border-radius:4px;font-size:11px;font-weight:bold;margin-left:4px">'
                           f'✓ CONFIRMADO {_conf_pct}%</span>')
        else:
            _conf_pct = _conf_match.get("confidence", 0)
            _conf_badge = (f'<span style="background:#6c757d;color:white;padding:2px 8px;'
                           f'border-radius:4px;font-size:11px;margin-left:4px">'
                           f'⚠ NÃO CONFIRMADO {_conf_pct}%</span>')
    return f'''<div class="vuln {f['severity']}">
  <h3>{html.escape(f.get('name',''))} <span class="source-badge {src_cls}">{f.get('source','')}</span> {badge(f['severity'])}{reclassify_badge}{_conf_badge}</h3>
  <table>{rows}
  </table></div>'''

vhtml = '<div class="info-box"><p>✅ Nenhuma vulnerabilidade encontrada no escopo analisado.</p></div>' if not all_f else     "".join(render_finding(f) for f in all_f)

# Tabela compacta para Low/Info agrupados
low_table_html = ""
if zap_low_groups:
    rows_low = "".join(
        f'<tr><td>{html.escape(name)}</td>'
        f'<td style="text-align:center">{grp["count"]}</td>'
        f'<td style="text-align:center">{badge(grp.get("sev", grp["finding"]["severity"]))}</td>'
        f'<td>{html.escape(grp["cve"])}</td>'
        f'<td>{html.escape(grp["conf"])}</td>'
        f'<td style="font-size:11px;color:#555">{"<br>".join(html.escape(u) for u in grp["urls"])}</td>'
        f'<td style="font-size:11px">{html.escape(grp["finding"]["remediation"] or "")}</td></tr>'
        for name, grp in sorted(zap_low_groups.items())
    )
    low_table_html = f'''<h2>4. Achados Baixo / Informativo — ZAP ({len(zap_low_groups)} tipos distintos, {sum(g["count"] for g in zap_low_groups.values())} ocorrências no total)</h2>
    <p style="color:#666;font-size:13px">Agrupados por tipo para reduzir ruído. Validar manualmente antes de reportar.</p>
    <table>
      <tr style="background:#f5f5f5"><th>Tipo de Alerta</th><th>Qtd</th><th>Sev</th><th>CVE / CWE</th><th>Confiança</th><th>URLs (amostra)</th><th>Recomendação</th></tr>
      {rows_low}
    </table>'''

# ── Gerar HTML: WAF & Email Security ────────────────────────
waf_email_html = ''

# WAF banner
if WAF_DETECTED and WAF_NAME:
    waf_email_html += (f'<div style="background:#fff3cd;border-left:5px solid #d4833a;'
        f'padding:14px 16px;border-radius:4px;margin:16px 0">'
        f'<strong style="color:#856404">🛡 WAF Detectado: {html.escape(WAF_NAME)}</strong>'
        f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
        f'O alvo está protegido por um Web Application Firewall. Achados do active scan '
        f'podem ter falsos negativos — vulnerabilidades de injeção podem ter sido bloqueadas '
        f'durante o scan sem serem detectadas.</p></div>')

# Email security
if email_security:
    sev_color = {'high':'#b34e4e','medium':'#d4833a','low':'#4a7c8c','none':'#27ae60'}
    sev_label = {'high':'ALTO','medium':'MÉDIO','low':'BAIXO','none':'OK','NOT_FOUND':'INFO'}
    email_rows = ''
    for proto, data in [('SPF', email_security.get('spf',{})),
                         ('DMARC', email_security.get('dmarc',{})),
                         ('DKIM',  email_security.get('dkim',{}))]:
        sev  = data.get('severity','none')
        stat = data.get('status','?')
        det  = data.get('detail','')
        rec  = data.get('recommendation','')
        val  = data.get('value','')
        sc   = sev_color.get(sev,'#999')
        sl   = sev_label.get(stat, sev_label.get(sev,'?'))
        email_rows += (f'<tr>'
            f'<td style="font-weight:bold;width:80px">{proto}</td>'
            f'<td style="text-align:center"><span style="background:{sc};color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{sl}</span></td>'
            f'<td>{html.escape(det)}</td>'
            f'<td style="font-size:11px;color:#555">{html.escape(rec) if rec else ("<code>"+html.escape(val)+"</code>" if val else "—")}</td>'
            f'</tr>')
    waf_email_html += (f'<h3>Segurança de Email — {html.escape(DOMAIN)}</h3>'
        '<table><tr style="background:#f5f5f5">'
        '<th>Protocolo</th><th>Status</th><th>Detalhe</th><th>Recomendação / Valor</th></tr>'
        + email_rows + '</table>')

if waf_email_html:
    waf_email_html = f'<h2>Infraestrutura & Segurança DNS</h2>' + waf_email_html

# ── Gerar HTML: Comportamento do Scan ─────────────────────────
scan_behavior_html = ""
if scan_meta:
    evasion_active = scan_meta.get("evasion_active", False)
    waf_n          = scan_meta.get("waf_name", "")
    techniques     = scan_meta.get("evasion_techniques", [])
    rl             = scan_meta.get("nuclei_rate_limit", 50)
    conc           = scan_meta.get("nuclei_concurrency", 10)
    delay          = scan_meta.get("nuclei_delay")
    ua             = scan_meta.get("user_agent", "")
    nuc_count      = scan_meta.get("nuclei_results_after_evasion")
    zap_count      = scan_meta.get("zap_results_after_evasion")

    TECH_LABELS = {
        "rate_limit_reduced":     ("🐢", "Rate limit reduzido",     f"Nuclei: {rl} req/s com delay randômico — imita tráfego humano"),
        "user_agent_rotation":    ("🔄", "User-Agent rotation",     f"UA de browser real: {ua[:60]}..." if len(ua)>60 else f"UA: {ua}"),
        "origin_spoofing":        ("🎭", "Origin spoofing",         "X-Forwarded-For: 127.0.0.1 + X-Real-IP: 127.0.0.1 injetados"),
        "payload_alterations":    ("🔀", "Payload alterations",     "Nuclei testou variações de encoding automaticamente (-pa)"),
        "waf_response_bypass":    ("⏭", "WAF response bypass",     "Respostas 403/406/429 ignoradas — scan não interrompe em bloqueios"),
        "zap_threads_reduced":    ("🧵", "ZAP threads reduzidas",   "Active scan com 2 threads — reduz assinatura de scan automatizado"),
    }

    if evasion_active:
        tech_rows = "".join(
            f'<tr>'
            f'<td style="font-size:18px;text-align:center;width:36px">{icon}</td>'
            f'<td style="font-weight:600;width:180px">{label}</td>'
            f'<td style="color:#555;font-size:13px">{desc}</td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">ATIVO</span></td>'
            f'</tr>'
            for t in techniques for icon, label, desc in [TECH_LABELS.get(t, ("","",""))]
            if label
        )

        results_row = ""
        if nuc_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{nuc_count}</div>'
                f'<div style="font-size:12px;color:#555">achados Nuclei\ncom evasão</div></div>')
        if zap_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{zap_count}</div>'
                f'<div style="font-size:12px;color:#555">alertas ZAP\ncom evasão</div></div>')

        scan_behavior_html = (
            f'<h2>🔬 Comportamento do Scan & Evasão Passiva</h2>'
            f'<div style="background:#fff8e6;border-left:5px solid #d4833a;'
            f'padding:16px;border-radius:4px;margin-bottom:16px">'
            f'<strong style="color:#856404">⚠ WAF Detectado: {html.escape(waf_n)}</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'O scanner detectou um WAF e ativou automaticamente o modo de evasão passiva. '
            f'As técnicas abaixo foram aplicadas para maximizar a cobertura e reduzir falsos negativos.</p></div>'
            f'<h3 style="color:#1a3a4f;margin-bottom:8px">Técnicas de Evasão Passiva Aplicadas</h3>'
            f'<table style="margin-bottom:16px"><tr style="background:#f5f5f5">'
            f'<th></th><th style="text-align:left">Técnica</th>'
            f'<th style="text-align:left">Detalhe</th><th>Status</th></tr>'
            + tech_rows +
            f'</table>'
            + (f'<h3 style="color:#1a3a4f;margin-bottom:8px">Resultados com Evasão Ativa</h3>'
               f'<div style="margin-bottom:8px">{results_row}</div>'
               f'<p style="font-size:12px;color:#888;margin:4px 0">Resultados obtidos após aplicação das técnicas de evasão. '
               f'Comparar com scans sem evasão não é aplicável pois o WAF teria bloqueado requests anteriores.</p>'
               if results_row else "")
        )
    else:
        # Sem WAF — registrar que scan foi direto
        scan_behavior_html = (
            f'<h2>🔬 Comportamento do Scan</h2>'
            f'<div style="background:#f0fff4;border-left:5px solid #27ae60;'
            f'padding:14px 16px;border-radius:4px">'
            f'<strong style="color:#1a7a4a">✓ Nenhum WAF Detectado — Scan Direto</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'O alvo não possui WAF identificado. O scan rodou com configurações padrão '
            f'(Nuclei {rl} req/s, concurrency {conc}). '
            f'Resultados têm alta confiança — sem filtros intermediários.</p></div>'
        )

errsec = "" if not errors else \
    '<h2>⚠ Avisos de Processamento</h2><div class="info-box" style="border-left-color:#d4833a"><ul>' + \
    "".join(f"<li><code>{html.escape(e)}</code></li>" for e in errors) + "</ul></div>"

# ── Gerar HTML: Análise JS ───────────────────────────────────
js_html = ""
if js_analysis:
    HIGH_JS_TYPES = {"AWS Access Key","AWS Secret","Private Key","Stripe Live Key",
        "GitHub Token","GitLab PAT","OpenAI Key","Anthropic Key","Hardcoded Password",
        "DB Connection String","Firebase Key","Slack Token"}
    def js_sev(t): return "high" if t in HIGH_JS_TYPES else "medium"
    def js_sev_color(s): return {"high":"#b34e4e","medium":"#d4833a"}.get(s,"#4a7c8c")
    def js_badge(t):
        s=js_sev(t); c=js_sev_color(s)
        lbl={"high":"ALTO","medium":"MÉDIO"}.get(s,"BAIXO")
        return f'<span style="background:{c};color:white;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:bold">{lbl}</span>'

    # Stat bar JS
    js_accessible = [p for p in js_probes if p.get("status")==200]
    js_exposed_api = [p for p in js_probes if p.get("status")==200 and p.get("is_json")]
    js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
    js_html = f'''<h2>JS / Frontend — Análise de Segurança</h2>
    <div class="info-box">
      <table>
        <tr><th style="width:200px">Arquivos JS analisados</th><td>{len(js_files_list)}</td></tr>
        <tr><th>Secrets / credenciais</th><td><span style="color:#b34e4e;font-weight:bold">{sum(1 for s in js_secrets if js_sev(s["type"])=="high")}</span> alto &nbsp;|&nbsp; <span style="color:#d4833a">{sum(1 for s in js_secrets if js_sev(s["type"])=="medium")}</span> médio</td></tr>
        <tr><th>Endpoints descobertos</th><td>{len(js_endpoints)} &nbsp;|&nbsp; {len(js_accessible)} acessíveis sem autenticação</td></tr>
        <tr><th>Frameworks detectados</th><td>{len(js_frameworks)} ({len(js_vuln_fw)} com CVE conhecida)</td></tr>
        <tr><th>Comentários sensíveis</th><td>{len(js_comments)}</td></tr>
      </table>
    </div>'''

    # Secrets
    if js_secrets:
        from collections import defaultdict
        by_type = defaultdict(list)
        for s in js_secrets: by_type[s["type"]].append(s)
        js_html += "<h3>Secrets e Credenciais Detectadas</h3>"
        for stype, items in sorted(by_type.items(), key=lambda x: 0 if js_sev(x[0])=="high" else 1):
            c = js_sev_color(js_sev(stype))
            js_html += (f'<div style="border-left:5px solid {c};padding:14px 16px;margin:12px 0;'
                f'background:#ffffff;border-radius:6px;border:1px solid #e0e0e0;box-shadow:0 1px 3px rgba(0,0,0,.06)">'
                f'<div style="margin-bottom:10px">'
                f'<strong style="font-size:14px">{html.escape(stype)}</strong> {js_badge(stype)}'
                f' <span style="color:#888;font-size:12px;margin-left:6px">({len(items)} ocorrência(s))</span>'
                f'</div>'
                f'<table style="width:100%;border-collapse:collapse">'
                f'<tr>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd;width:35%">Valor / Pattern</th>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd">Contexto no Código</th>'
                f'</tr>')
            for item in items:
                v    = item["value"]
                ctx  = item.get("context", "")
                furl = item.get("url", "")
                js_html += (
                    f'<tr>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top;background:#fafafa">'
                    f'<code style="font-size:11px;color:#c0392b;background:#fff5f5;padding:3px 6px;'
                    f'border-radius:3px;word-break:break-all;display:block">{html.escape(v)}</code>'
                    + (f'<div style="font-size:10px;color:#888;margin-top:5px">📄 {html.escape(furl)}</div>' if furl else "")
                    + f'</td>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top">'
                    f'<pre style="margin:0;font-size:10px;font-family:monospace;background:#f8f9fa;'
                    f'color:#333;padding:6px 8px;border-radius:3px;white-space:pre-wrap;'
                    f'word-break:break-all;border:1px solid #e0e0e0;max-height:160px;'
                    f'overflow-y:auto">{html.escape(ctx) if ctx else "—"}</pre>'
                    + f'</td></tr>')
            js_html += "</table></div>"

    # Frameworks
    if js_frameworks:
        seen_fw = {}
        fw_rows = ""
        for fw in js_frameworks:
            k = (fw["framework"],fw["version"])
            if k in seen_fw: continue
            seen_fw[k]=True
            vuln_html = ('<span style="color:#b34e4e;font-weight:bold">⚠ ' +
                ', '.join(v["cve"] for v in fw.get("vulns",[])) + '</span>')\
                if fw.get("vulnerable") else '<span style="color:#27ae60">✓ OK</span>'
            fw_rows += (f'<tr><td><strong>{html.escape(fw["framework"])}</strong></td>'
                f'<td><code>{html.escape(fw["version"])}</code></td>'
                f'<td>{vuln_html}</td></tr>')
        js_html += ('<h3>Frameworks Detectados</h3>'
            '<table><tr style="background:#f5f5f5"><th>Framework</th><th>Versão</th><th>Status</th></tr>'
            + fw_rows + '</table>')

    # Endpoints acessíveis
    if js_accessible:
        ep_rows = "".join(
            f'<tr><td><code style="font-size:11px;word-break:break-all">{html.escape(p["url"])}</code></td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:1px 6px;border-radius:3px;font-size:11px">{p["status"]}</span></td>'
            f'<td style="font-size:11px">{"JSON API" if p.get("is_json") else "HTML"}</td></tr>'
            for p in js_accessible[:15])
        js_html += ('<h3>Endpoints Acessíveis Sem Autenticação</h3>'
            '<table><tr style="background:#f5f5f5"><th>URL</th><th>HTTP</th><th>Tipo</th></tr>'
            + ep_rows + '</table>')

    # Comentários sensíveis
    if js_comments:
        comm_rows = "".join(
            f'<tr><td style="padding:6px 10px;border-bottom:1px solid #eee">'
            f'<code style="font-size:11px;background:#f8f9fa;color:#c0392b;'
            f'padding:3px 6px;border-radius:3px;display:block;white-space:pre-wrap;'
            f'word-break:break-all;border:1px solid #e0e0e0">{html.escape(c["comment"])}</code>'
            f'<div style="font-size:10px;color:#888;margin-top:3px">📄 {html.escape(c.get("url",""))}</div>'
            f'</td></tr>'
            for c in js_comments[:10])
        js_html += ('<h3>Comentários Sensíveis no Código</h3>'
            '<table style="width:100%;border-collapse:collapse;border:1px solid #eee;border-radius:6px">'
            + comm_rows + '</table>')

# ── Gerar HTML: TLS ─────────────────────────────────────────
SEV_TLS_CLASS = {"critical":"tls-critical","high":"tls-high","medium":"tls-warn","low":"tls-warn","info":"tls-ok"}
if tls_findings:
    TLS_SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","WARN":"AVISO","LOW":"BAIXO","OK":"OK","INFO":"INFO"}
    tls_rows = "".join(
        f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(f["id"])}</td>'
        f'<td class="{SEV_TLS_CLASS.get(f["sev"],"tls-ok")}">{html.escape(TLS_SEV_PT.get(f["sev_raw"].upper(),f["sev_raw"]))}</td>'
        f'<td>{html.escape(f["finding"])}</td>'
        f'<td>{html.escape(f["cve"] or "—")}</td></tr>'
        for f in tls_findings
    )
    tls_html = f'''<h2>TLS / SSL — {len(tls_findings)} problema(s) identificado(s)</h2>
    <table>
      <tr style="background:#f5f5f5"><th>Identificador</th><th>Severidade</th><th>Achado</th><th>CVE</th></tr>
      {tls_rows}
    </table>'''
else:
    tls_html = ""

# ── Gerar HTML: Confirmações de Exploit ──────────────────────

# Mapa de razões legíveis por poc_note / http_status para itens não confirmados
def _unconfirmed_reason(c):
    """
    Retorna (titulo, detalhe) explicando por que o achado não foi confirmado.
    Baseado em poc_note, http_status, vuln_type e confidence.
    """
    note       = (c.get("poc_note") or "").strip()
    status     = str(c.get("http_status") or "")
    vuln_type  = (c.get("vuln_type") or "")
    confidence = int(c.get("confidence") or 0)
    dc         = c.get("double_checked", False)
    diff       = c.get("diff_changed", False)

    # Timeout / erro de rede
    if status in ("TIMEOUT", "000", "ERR") or "timeout" in note.lower():
        return (
            "Endpoint inacessível durante a re-execução",
            "O alvo não respondeu dentro do limite de tempo nas duas tentativas de confirmação. "
            "A vulnerabilidade pode existir mas não pôde ser verificada ativamente. "
            "Verifique manualmente se o endpoint ainda está acessível."
        )

    # Endpoint bloqueado / autenticação
    if status in ("401", "403"):
        return (
            f"Endpoint retornou HTTP {status} — acesso negado",
            "O scanner não conseguiu acessar o recurso durante a confirmação. "
            "Pode indicar que o endpoint exige autenticação ou que o IP do scanner foi bloqueado. "
            "Recomenda-se verificação manual com sessão autenticada."
        )

    # Sem diff de response
    if not diff and vuln_type in ("auth_bypass", "generic", "exposure", "redirect"):
        return (
            "Sem diferença de comportamento detectada",
            f"O payload foi enviado mas a resposta (HTTP {status}) não diferiu do baseline. "
            "Sem evidência de desvio de comportamento, o achado não pôde ser confirmado como ativo. "
            "Pode ser falso positivo do scanner — recomenda-se revisão manual."
        )

    # Security header — informacional
    if vuln_type == "security_header":
        return (
            "Achado informacional — sem PoC ativo",
            "Headers de segurança ausentes são verificados passivamente via inspeção de response. "
            "Não há payload de ataque para re-executar. "
            "A presença ou ausência do header é a própria evidência — consulte a seção de Vulnerabilidades."
        )

    # TLS — endpoint inacessível
    if vuln_type == "tls" and status not in ("200","301","302","403"):
        return (
            f"Endpoint TLS inacessível (HTTP {status})",
            "Não foi possível estabelecer conexão TLS com o alvo durante a re-execução. "
            "O achado foi detectado pelo testssl mas não pôde ser confirmado via re-conexão ativa."
        )

    # Email / DNS
    if vuln_type == "email":
        return (
            "Registro DNS presente — issue pode ter sido corrigida",
            "A re-verificação via dig encontrou o registro DNS necessário. "
            "O achado foi filtrado como não confirmado pois o problema pode ter sido corrigido após o scan inicial."
        )

    # Confiança abaixo do mínimo
    if confidence < 60:
        return (
            f"Confiança insuficiente para confirmação ({confidence}%)",
            f"O validador obteve resposta HTTP {status} mas não encontrou evidências suficientes "
            f"para confirmar a vulnerabilidade com segurança (mínimo: 60%). "
            f"Motivo técnico: {note or 'sem detalhe adicional'}. "
            "Recomenda-se revisão manual antes de reportar ao time."
        )

    # Fallback genérico
    return (
        "Sem evidência suficiente para confirmação",
        f"{note or 'O validador não identificou padrões ou diferenças de comportamento que confirmem a vulnerabilidade.'} "
        f"(HTTP {status}) — Revisar manualmente."
    )

if confirmations:
    conf_rows_confirmed   = ""
    conf_rows_unconfirmed = ""

    for c in confirmations:
        sev_colors = {"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#888"}
        sev_c = sev_colors.get(c.get("severity","info"),"#888")

        template_cell = (
            f'<td style="vertical-align:top;width:160px">'
            f'  <code style="font-size:12px">{html.escape(str(c.get("template_id","—")))}</code><br>'
            f'  <span style="background:{sev_c};color:white;padding:1px 6px;border-radius:3px;font-size:10px">'
            f'  {str(c.get("severity","info")).upper()}</span>'
            f'</td>'
        )
        url_cell = (
            f'<td style="vertical-align:top">'
            f'<code style="font-size:11px;word-break:break-all">{html.escape(str(c.get("url","—")))}</code>'
            f'</td>'
        )

        if c.get("confirmed"):
            # ── CONFIRMADO: exibir status, confiança e evidências completas ──
            conf   = int(c.get("confidence", 0))
            vt     = c.get("vuln_type", "")
            status = str(c.get("http_status","—"))

            evidence_html = ""
            if c.get("response_headers"):
                evidence_html += (
                    f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Response Headers</div>'
                    f'<div class="evidence-box" style="margin-bottom:8px">{html.escape(c["response_headers"])}</div>'
                )
            if c.get("response_body"):
                evidence_html += (
                    f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Response Body</div>'
                    f'<div class="evidence-box">{html.escape(c["response_body"])}</div>'
                )

            curl_repr = c.get("curl_reproducible") or c.get("curl_command","")
            curl_html = (
                f'<div style="font-size:11px;font-weight:600;color:#555;margin:8px 0 3px">Reproduzir:</div>'
                f'<div class="evidence-box" style="background:#1e3a4f;color:#a8d8ea;font-size:11px">'
                f'{html.escape(curl_repr)}</div>'
            ) if curl_repr else ""

            conf_rows_confirmed += (
                f'<tr style="background:#f0fff4">'
                + template_cell + url_cell +
                f'<td style="text-align:center;vertical-align:top;width:110px">'
                f'  <span style="background:#27ae60;color:white;padding:3px 8px;border-radius:4px;'
                f'  font-size:11px;font-weight:bold;white-space:nowrap">✓ CONFIRMADO</span><br>'
                f'  <code style="font-size:13px;font-weight:bold;color:#27ae60">{html.escape(status)}</code>'
                f'</td>'
                f'<td style="text-align:center;vertical-align:top;width:80px">'
                f'<div style="font-size:24px;font-weight:bold;color:{"#27ae60" if conf>=80 else "#d4833a"}">{conf}%</div>'
                f'<div style="font-size:10px;color:#888;margin-top:2px">{html.escape(vt)}</div>'
                f'</td>'
                f'<td style="vertical-align:top">'
                f'<div style="background:#f0fff4;border-left:3px solid #27ae60;padding:6px 10px;border-radius:3px;font-size:12px;margin-bottom:8px">'
                f'<strong>Nota:</strong> {html.escape(c.get("poc_note","—"))}</div>'
                f'{evidence_html}{curl_html}'
                f'</td>'
                f'</tr>'
            )
        else:
            # ── NÃO CONFIRMADO: apenas aviso com justificativa, sem evidências ──
            reason_title, reason_detail = _unconfirmed_reason(c)
            conf_rows_unconfirmed += (
                f'<tr style="background:#fafafa">'
                + template_cell + url_cell +
                f'<td colspan="3" style="vertical-align:top;background:#fff8f0">'
                f'<div style="display:flex;align-items:flex-start;gap:12px">'
                f'<span style="font-size:20px;margin-top:2px">⚠</span>'
                f'<div>'
                f'<div style="font-weight:600;color:#856404;font-size:13px;margin-bottom:4px">'
                f'Não confirmado — {html.escape(reason_title)}</div>'
                f'<div style="font-size:12px;color:#555;line-height:1.6">{html.escape(reason_detail)}</div>'
                f'</div></div>'
                f'</td>'
                f'</tr>'
            )

    n_conf = sum(1 for c in confirmations if c.get("confirmed"))
    n_total = len(confirmations)

    # Montar tabela: confirmados primeiro, depois não-confirmados com separador
    separator = ""
    if conf_rows_confirmed and conf_rows_unconfirmed:
        separator = (
            f'<tr><td colspan="5" style="background:#f0f2f5;padding:6px 12px;'
            f'font-size:11px;color:#888;font-style:italic;border:none">'
            f'▼ Achados abaixo não puderam ser confirmados ativamente — revisar manualmente antes de reportar</td></tr>'
        )

    confirm_html = (
        f'<h2>Confirmação Ativa de Exploits ({n_conf}/{n_total} confirmados)</h2>'
        f'<p style="color:#666;font-size:13px">Achados confirmados incluem status HTTP, confiança e evidência completa. '
        f'Achados não confirmados exibem apenas a justificativa técnica — sem evidência disponível para reporte.</p>'
        f'<table>'
        f'<tr style="background:#f5f5f5">'
        f'<th style="width:160px">Template</th>'
        f'<th>URL</th>'
        f'<th style="width:110px">Status</th>'
        f'<th style="width:80px">Confiança</th>'
        f'<th>Evidência & Nota PoC</th></tr>'
        + conf_rows_confirmed
        + separator
        + conf_rows_unconfirmed +
        f'</table>'
    )
else:
    confirm_html = (
        f'<h2>Confirmação Ativa de Exploits</h2>'
        f'<div style="background:#f5f5f5;border-left:4px solid #888;padding:14px 16px;'
        f'border-radius:4px;color:#666;font-size:13px">'
        f'<strong>Nenhum achado elegível para confirmação ativa.</strong><br>'
        f'A confirmação ativa roda apenas em achados Nuclei com severidade '
        f'Crítica, Alta ou Média que incluam curl-command. '
        f'Se o scan usou apenas o ZAP, os achados aparecem na seção de '
        f'Vulnerabilidades Identificadas com evidência de request/response completo.'
        f'</div>'
    )


# ── Gerar HTML: Plano de Ação Priorizado ─────────────────────────
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

# Coletar todos os achados acionáveis por prazo
# v3: confirmados pelo poc_validator aparecem primeiro
def _sort_confirmed_first(items):
    """Coloca achados confirmados antes dos não confirmados."""
    def _is_confirmed(item):
        _c = _get_confirmation(item)
        return bool(_c and _c.get("confirmed"))
    return sorted(items, key=lambda x: (not _is_confirmed(x), x.get("severity","info")))

imediato = _sort_confirmed_first([f for f in all_f if f["severity"] in ("critical","high")])
sprint    = _sort_confirmed_first([f for f in all_f if f["severity"] == "medium"])
backlog   = [f for f in zap_low_groups.values() if f["sev"] in ("low","info")]

def action_card(title, icon, color, bg, items, prazo, descricao):
    if not items: return ""
    rows = ""
    seen_names = set()
    for item in items[:10]:
        name = item.get("name","") if isinstance(item,dict) and "name" in item else item.get("finding",{}).get("name","")
        if name in seen_names: continue
        seen_names.add(name)
        count = item.get("affected_count",1) if isinstance(item,dict) and "affected_count" in item else item.get("count",1)
        sev_f = item.get("severity","") if "severity" in item else item.get("sev","")
        count_str = f" <span style='color:#666;font-size:11px'>({count} ocorrência(s))</span>" if count > 1 else ""
        rows += f"<li style='margin:4px 0'><strong>{html.escape(name)}</strong>{count_str}</li>"
    return f"""<div style="border-left:5px solid {color};padding:16px;margin:12px 0;background:{bg};border-radius:4px">
  <h3 style="margin:0 0 6px;color:{color}">{icon} {html.escape(title)} <span style="font-size:12px;font-weight:normal;color:#666">— Prazo: {prazo}</span></h3>
  <p style="margin:0 0 10px;font-size:13px;color:#555">{descricao}</p>
  <ul style="margin:0;padding-left:20px;font-size:13px">{rows}</ul>
</div>"""

plan_parts = []
plan_parts.append(action_card(
    "Ação Imediata","🔴","#7a2e2e","#fff0f0",
    imediato,"esta semana",
    "Vulnerabilidades críticas e altas com potencial de comprometimento direto. Paralisar deploy se necessário."
))
plan_parts.append(action_card(
    "Próximo Sprint","🟡","#d4833a","#fff8f0",
    sprint,"próximas 2 semanas",
    "Achados médios que reduzem superfície de ataque. Incluir nas próximas histórias do time."
))
plan_parts.append(action_card(
    "Backlog de Segurança","🔵","#4a7c8c","#f0f8ff",
    backlog,"próximos 30 dias",
    "Melhorias de hardening e headers. Agendar como dívida técnica de segurança."
))

action_plan_html = ""
if any(plan_parts):
    action_plan_html = f"""<h2>Plano de Ação para o Time</h2>
<div class="info-box">
  <p>Priorização baseada em CVSS + EPSS + confirmação ativa. Achados com badge <strong style="color:#155724">✓ CONFIRMADO</strong> foram re-executados e validados — priorize estes para reporte imediato ao time de desenvolvimento.</p>
</div>
{"".join(plan_parts)}"""

page = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<title>SWARM — {html.escape(DOMAIN)}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}}
.container{{max-width:1200px;margin:0 auto;background:white;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.header{{background:#1a3a4f;color:white;padding:30px;text-align:center}}.header h1{{margin:0 0 10px}}
.content{{padding:30px}}
.stats{{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}}
.stat-card{{flex:1;padding:20px;text-align:center;color:white;border-radius:8px;min-width:100px}}
.stat-card.critical{{background:#7a2e2e}}.stat-card.high{{background:#b34e4e}}
.stat-card.medium{{background:#d4833a}}.stat-card.low{{background:#4a7c8c}}.stat-card.info{{background:#6e8f72}}
.stat-card .number{{font-size:36px;font-weight:bold}}
.info-box{{background:#e8f4f8;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #1a3a4f}}
.vuln{{border:1px solid #ddd;margin:20px 0;padding:20px;border-radius:8px;background:#fafafa}}
.vuln.critical{{border-left:10px solid #7a2e2e}}.vuln.high{{border-left:10px solid #b34e4e}}
.vuln.medium{{border-left:10px solid #d4833a}}.vuln.low{{border-left:10px solid #4a7c8c}}.vuln.info{{border-left:10px solid #6e8f72}}
.vuln h3{{margin-top:0}}.source-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-left:8px}}
.source-nuclei{{background:#3498db;color:white}}.source-zap{{background:#e74c3c;color:white}}
.footer{{background:#f5f5f5;padding:20px;text-align:center;font-size:12px;color:#666}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}th,td{{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5;font-weight:600}}h2{{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px}}
.risk-bar-wrap{{background:#e0e0e0;border-radius:4px;height:12px;margin:8px 0}}
.risk-bar{{background:{scol};height:12px;border-radius:4px;width:{risk}%}}
code{{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:12px}}
    .evidence-box{{background:#2d3436;color:#dfe6e9;padding:10px 14px;font-family:monospace;font-size:12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
    .tls-ok{{color:#27ae60;font-weight:bold}}.tls-warn{{color:#d4833a;font-weight:bold}}
    .tls-high{{color:#b34e4e;font-weight:bold}}.tls-critical{{color:#7a2e2e;font-weight:bold}}
    .confirm-yes{{background:#27ae60;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
    .confirm-no{{background:#95a5a6;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
</style></head><body><div class="container">
<div class="header"><h1>SWARM — Relatório de Segurança</h1>
<p>Alvo: <strong>{html.escape(TARGET)}</strong> | Domínio: {html.escape(DOMAIN)}</p>
<p>Data: {rdate} &nbsp;|&nbsp; Duração: {duration_str} &nbsp;|&nbsp; <strong>CONFIDENCIAL</strong></p></div>
<div class="content">
<h2>1. Sumário Executivo</h2>
<div class="stats">
{f'<div class="stat-card" style="background:#7a0000;border:2px solid #ff4444"><div class="number">{kev_count}</div><div>🔴 KEV</div></div>' if kev_count > 0 else ""}
<div class="stat-card critical"><div class="number">{stats['critical']}</div><div>CRÍTICO</div></div>
<div class="stat-card high"><div class="number">{stats['high']}</div><div>ALTO</div></div>
<div class="stat-card medium"><div class="number">{stats['medium']}</div><div>MÉDIO</div></div>
<div class="stat-card low"><div class="number">{stats['low']}</div><div>BAIXO</div></div>
<div class="stat-card info"><div class="number">{stats['info']}</div><div>INFO</div></div>
{f'<div class="stat-card" style="background:#155724"><div class="number">{n_confirmed_findings}</div><div>✓ Conf.</div></div>' if n_confirmed_findings > 0 else ""}
</div>
{f'<div style="background:#7a0000;color:white;padding:14px 18px;border-radius:6px;margin:12px 0;border-left:6px solid #ff4444"><strong style="font-size:14px">🔴 {kev_count} CVE(S) COM EXPLORAÇÃO ATIVA CONFIRMADA — CISA KEV</strong><br><span style="font-size:12px;opacity:.9">Estes CVEs estão no catálogo Known Exploited Vulnerabilities da CISA. Independente do score CVSS, exigem ação imediata: ' + ", ".join(f"<code style=\'background:rgba(255,255,255,.15);padding:1px 4px;border-radius:3px\'>{html.escape(cid)}</code>" for cid in list(kev_matches.keys())[:10]) + (f" e mais {len(kev_matches)-10}" if len(kev_matches)>10 else "") + "</span></div>" if kev_count > 0 else ""}
<div class="info-box">
<p><strong>Índice de Risco (0–100):</strong> {risk} <small style="color:#888;font-size:11px">(metodologia: KEV + EPSS + CVSS + JS)</small></p>
<div class="risk-bar-wrap"><div class="risk-bar"></div></div>
<p><strong>Total de Achados:</strong> {total} &nbsp;|&nbsp; <strong>Status:</strong> <span style="color:{scol};font-weight:bold">{stxt}</span></p>
<p><strong>Duração total do scan:</strong> {duration_str}</p>
<p><strong>Ferramentas:</strong> Nuclei + OWASP ZAP{"+ wafw00f" if WAF_DETECTED or os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}{"+ Katana" if KATANA_URLS > 0 else ""}{"+ JS/Secrets" if js_analysis else ""}{"+ testssl" if TLS_ISSUES >= 0 and os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}{"+ OpenAPI" if OPENAPI_FOUND else ""}</p>
<p><strong>Exploits verificados ativamente:</strong> {CONFIRMED_COUNT} re-executados com resposta capturada</p>
{'<p style="background:#fff3cd;padding:8px 12px;border-radius:4px;margin:8px 0;font-size:13px"><strong style="color:#856404">🛡 WAF: '+html.escape(WAF_NAME)+'</strong> — active scan pode ter falsos negativos.</p>' if WAF_DETECTED and WAF_NAME else ""}
{'<p style="color:#b34e4e;font-size:13px">⚠ <strong>'+str(EMAIL_ISSUES)+' problema(s) de segurança de email</strong> detectado(s).</p>' if EMAIL_ISSUES > 0 else ""}
</div>
<h2>2. Superfície de Ataque</h2>
<table>
<tr><th style="width:220px">Subdomínios descobertos</th><td>{SUB_COUNT}</td></tr>
<tr><th>Subdomínios ativos (HTTP)</th><td>{ACTIVE_COUNT}</td></tr>
<tr><th>Portas abertas</th><td><code>{html.escape(OPEN_PORTS)}</code></td></tr>
{f'<tr><th>URLs (Katana JS crawl)</th><td>{KATANA_URLS} URL(s) descobertas com rendering JS</td></tr>' if KATANA_URLS > 0 else ""}</table>
<h3>Hosts Ativos (httpx)</h3><table><tr><th>Resultado</th></tr>{trows(httpx_lines,"httpx não executado ou sem resultados detectados")}</table>
<h3>Portas Abertas e Serviços (nmap)</h3><table><tr><th>Porta / Serviço</th></tr>{trows(nmap_lines,"nmap não executado ou sem portas abertas")}</table>
<h2>3. Vulnerabilidades Identificadas</h2>{vhtml}

<!-- Comportamento do Scan -->
{scan_behavior_html}

<!-- WAF + Email Security -->
{waf_email_html}

<!-- TLS Section -->
{tls_html}

<!-- Exploit Confirmations -->
{confirm_html}


<!-- JS Analysis -->
{js_html}
{errsec}
{low_table_html}

<!-- Plano de Ação -->
{action_plan_html}
<h2>5. Arquivos de Evidência</h2><div class="info-box"><ul>
<li><code>raw/subdomains.txt</code> — Subdomínios descobertos</li>
<li><code>raw/httpx_results.txt</code> — Hosts HTTP ativos e tecnologias</li>
<li><code>raw/nmap.txt</code> — Scan de portas e serviços</li>
<li><code>raw/nuclei.json</code> — Achados do Nuclei (JSONL bruto)</li>
<li><code>raw/zap_alerts.json</code> — Alertas do OWASP ZAP (JSON bruto)</li>
<li><code>raw/zap_evidencias.xml</code> — Relatório completo do ZAP (XML)</li>
{"<li><code>raw/testssl.json</code> — Análise TLS/SSL (testssl)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}
{"<li><code>raw/kev_matches.json</code> — CVEs com exploração ativa confirmada (CISA KEV)</li>" if kev_matches else ""}
{"<li><code>raw/cve_enrichment.json</code> — Dados CVE (CVSS + EPSS) do NVD/FIRST</li>" if cve_enrichment else ""}
{"<li><code>raw/exploit_confirmations.json</code> — Resultados de confirmação ativa de exploits</li>" if confirmations else ""}
{"<li><code>raw/openapi_spec.json</code> — Especificação OpenAPI/Swagger importada</li>" if OPENAPI_FOUND else ""}
{"<li><code>raw/scan_metadata.json</code> — Comportamento e configuração de evasão do scan</li>" if scan_meta else ""}
{"<li><code>raw/waf.json</code> — Detecção de WAF (wafw00f)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}
{"<li><code>raw/email_security.json</code> — SPF/DMARC/DKIM</li>" if email_security else ""}
{"<li><code>raw/katana_urls.txt</code> — URLs descobertas pelo Katana (JS crawl)</li>" if KATANA_URLS > 0 else ""}
{"<li><code>raw/ffuf.json</code> — Endpoints descobertos por fuzzing (ffuf)</li>" if FFUF_FOUND > 0 else ""}
{"<li><code>raw/smuggler.txt</code> — Análise HTTP Request Smuggling</li>" if SMUGGLER_FOUND else ""}
{"<li><code>raw/trufflehog.json</code> — Secrets de alta confiança (trufflehog)</li>" if TRUFFLEHOG_FOUND > 0 else ""}
{"<li><code>raw/js_analysis.json</code> — Análise JS/Secrets completa</li>" if js_analysis else ""}
{"<li><code>raw/js_files/</code> — Arquivos JS para análise forense</li>" if js_files_list else ""}
</ul>
<p><strong>Nota:</strong> Todos os achados devem ser validados manualmente antes de reportar ao cliente ou equipe de desenvolvimento.</p></div></div>
<div class="footer"><p><strong>CONFIDENCIAL — USO INTERNO</strong></p>
<p>SWARM — Scanner Automatizado de Segurança</p></div></div></body></html>"""

out = os.path.join(OUTDIR,"relatorio_swarm.html")
open(out,"w",encoding="utf-8").write(page)
print(f"[✓] Relatório: {out}")
print(f"[✓] {total} vulnerabilidade(s) | C={stats['critical']} A={stats['high']} M={stats['medium']} B={stats['low']} I={stats['info']}")
if errors: print(f"[!] {len(errors)} aviso(s) — ver relatório")

# ── findings.json — schema fixo para integração SaaS/SIEM ────────
findings_schema = {
    "schema_version": "1.0",
    "scan": {
        "target": TARGET, "domain": DOMAIN,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk,
        "risk_level": stxt.split(" — ")[0] if " — " in stxt else stxt,
        "waf_detected": WAF_DETECTED, "waf_name": WAF_NAME,
        "phase_times": phase_times,
    },
    "summary": {
        "total": total,
        "critical": stats["critical"], "high": stats["high"],
        "medium": stats["medium"],    "low": stats["low"],
        "info": stats["info"],        "kev_count": kev_count,
        "confirmed": n_confirmed_findings,
        "poc_validator_ran": len(confirmations) > 0,
    },
    "findings": [
        {"id": f.get("id",""), "name": f.get("name",""), "severity": f.get("severity",""),
         "source": f.get("source",""), "url": f.get("url",""),
         "cve_ids": f.get("cve_ids",[]), "cvss": f.get("cvss"),
         "epss": f.get("epss_score"), "in_kev": f.get("in_kev",False),
         "description": f.get("description",""),
         "remediation": f.get("remediation",""),
         "risk_score": f.get("risk_score",0)}
        for f in all_f
    ],
    "confirmations": [
        {"template_id": c.get("template_id",""), "url": c.get("url",""),
         "severity": c.get("severity",""), "confirmed": c.get("confirmed",False),
         "confidence": c.get("confidence",0), "poc_note": c.get("poc_note",""),
         "http_status": c.get("http_status",""),
         "curl_reproducible": c.get("curl_reproducible","")}
        for c in confirmations
    ],
    "security_headers": security_headers_data,
}
findings_file = os.path.join(OUTDIR,"findings.json")
json.dump(findings_schema, open(findings_file,"w",encoding="utf-8"), ensure_ascii=False, indent=2, default=str)
print(f"[✓] JSON estruturado: {findings_file}")

# ── sumario_executivo.html — 1 página para gestores ──────────────
exec_file = os.path.join(OUTDIR,"sumario_executivo.html")
rc = "#7a2e2e" if risk>=70 else ("#b34e4e" if risk>=40 else ("#d4833a" if risk>=15 else "#27ae60"))
kev_list_str = ", ".join(list(kev_matches.keys())[:5]) if kev_matches else "Nenhum"
top_f = [f for f in all_f if f["severity"] in ("critical","high")][:8]
sev_bg = {"critical":"#7a2e2e","high":"#b34e4e"}
sev_lb = {"critical":"CRÍTICO","high":"ALTO"}
top_rows = "".join(
    f'<tr><td><span style="background:{sev_bg.get(f["severity"],"#888")};color:white;'
    f'padding:2px 8px;border-radius:4px;font-size:11px">{sev_lb.get(f["severity"],f["severity"].upper())}</span></td>'
    f'<td style="font-weight:600">{html.escape(f["name"])}</td>'
    f'<td style="color:#555;font-size:12px">{html.escape(f.get("impact","") or "Ver relatório técnico")}</td>'
    f'<td style="font-size:11px">{html.escape((f.get("remediation","") or "")[:60])}</td></tr>'
    for f in top_f
) or '<tr><td colspan="4" style="text-align:center;color:#888">Sem achados críticos ou altos</td></tr>'
phase_rows = "".join(
    f'<tr><td>{"Descob./Sup./TLS/Nuclei/Conf./CVE/WAF/Email/ZAP/JS/Compl./Rel.".split("/")[["P1","P2","P3","P4","P5","P6","P7","P8","P9","P10","P10_5","P11"].index(p)] if p in ["P1","P2","P3","P4","P5","P6","P7","P8","P9","P10","P10_5","P11"] else p}</td><td>{d//60}m {d%60:02d}s</td></tr>'
    for p,d in phase_times.items()
) if phase_times else ""
exec_page = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<title>Sumário Executivo — {html.escape(DOMAIN)}</title>
<style>
body{{font-family:"Segoe UI",sans-serif;max-width:850px;margin:0 auto;padding:30px;color:#333}}
h1{{color:#1a3a4f;font-size:22px;border-bottom:3px solid #1a3a4f;padding-bottom:8px}}
h2{{color:#1a3a4f;font-size:15px;margin-top:24px}}
.kpi{{display:inline-block;text-align:center;margin:0 10px;padding:10px 18px;background:#f5f5f5;border-radius:8px}}
.kpi .n{{font-size:26px;font-weight:bold}}
.kpi .l{{font-size:11px;color:#888}}
table{{width:100%;border-collapse:collapse;margin:8px 0}}
th{{background:#1a3a4f;color:white;padding:8px;text-align:left;font-size:12px}}
td{{border:1px solid #eee;padding:8px;font-size:12px}}
.footer{{color:#aaa;font-size:10px;text-align:center;margin-top:32px;border-top:1px solid #eee;padding-top:8px}}
@media print{{body{{padding:0}}}}
</style></head><body>
<div style="background:#1a3a4f;color:white;padding:18px;border-radius:8px;margin-bottom:20px">
<h1 style="color:white;border:none;margin:0 0 4px">Sumário Executivo de Segurança</h1>
<p style="margin:0;opacity:.8;font-size:13px">{html.escape(TARGET)} &nbsp;·&nbsp; {datetime.now().strftime("%d/%m/%Y %H:%M")} &nbsp;·&nbsp; CONFIDENCIAL</p>
</div>
<h2>Índice de Risco</h2>
<div style="margin:8px 0">
<span style="background:{rc};color:white;font-size:32px;font-weight:bold;padding:10px 22px;border-radius:6px">{risk}/100</span>
<span style="margin-left:14px;font-size:15px;font-weight:600;color:{rc}">{html.escape(stxt)}</span>
</div>
<h2>Achados</h2>
<div style="margin:8px 0">
<div class="kpi"><div class="n" style="color:#7a2e2e">{stats["critical"]}</div><div class="l">CRÍTICO</div></div>
<div class="kpi"><div class="n" style="color:#b34e4e">{stats["high"]}</div><div class="l">ALTO</div></div>
<div class="kpi"><div class="n" style="color:#d4833a">{stats["medium"]}</div><div class="l">MÉDIO</div></div>
<div class="kpi"><div class="n" style="color:#4a7c8c">{stats["low"]}</div><div class="l">BAIXO</div></div>
{"<div class='kpi'><div class='n' style='color:#155724'>" + str(n_confirmed_findings) + "</div><div class='l'>✓ Confirmados</div></div>" if n_confirmed_findings > 0 else ""}
{"<div class='kpi'><div class='n' style='color:#7a0000'>" + str(kev_count) + "</div><div class='l'>🔴 KEV</div></div>" if kev_count > 0 else ""}
</div>
{"<p style='background:#fff0f0;padding:10px;border-radius:6px;border-left:4px solid #7a0000;font-size:12px'><strong>⚠ Exploração Ativa (CISA KEV):</strong> " + kev_list_str + "</p>" if kev_count > 0 else ""}
<h2>Principais Vulnerabilidades</h2>
<table><tr><th>Severidade</th><th>Vulnerabilidade</th><th>Impacto</th><th>Correção</th></tr>{top_rows}</table>
<h2>Recomendações</h2>
<ol style="font-size:13px;line-height:2">
{"<li><strong>URGENTE:</strong> Remediar " + str(kev_count) + " CVE(s) com exploração ativa: " + kev_list_str + "</li>" if kev_count > 0 else ""}
{"<li>Corrigir " + str(stats["critical"]) + " achado(s) crítico(s) — prazo imediato</li>" if stats["critical"] > 0 else ""}
{"<li>Planejar " + str(stats["high"]) + " achado(s) alto(s) — esta sprint</li>" if stats["high"] > 0 else ""}
{"<li>Agendar " + str(stats["medium"]) + " achado(s) médio(s) — próxima sprint</li>" if stats["medium"] > 0 else ""}
<li>Consultar relatório técnico para evidências detalhadas e comandos de reprodução</li>
</ol>
{"<h2>Tempo por Fase</h2><table><tr><th>Fase</th><th>Duração</th></tr>" + phase_rows + "</table>" if phase_rows else ""}
<div class="footer">Gerado por SWARM · Uso restrito a equipes de segurança autorizadas · CONFIDENCIAL</div>
</body></html>"""
open(exec_file,"w",encoding="utf-8").write(exec_page)
print(f"[✓] Sumário executivo: {exec_file}")
