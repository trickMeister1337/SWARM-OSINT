# SWARM OSINT

**Pre-Engagement Intelligence Collector** — coleta de inteligência passiva/semi-ativa executada antes do engajamento ativo com [swarm.sh](https://github.com/trickMeister1337/swarm).

> ⚠️ **USO EXCLUSIVO EM AMBIENTES AUTORIZADOS** — Requer Rules of Engagement (RoE) assinado. Uso sem autorização é crime (Art. 154-A CP).

---

## Posição no Pipeline

```
SWARM OSINT  →  swarm.sh  →  swarm_red.sh
 (passivo)       (recon)      (exploração)
```

O `osint.sh` roda **antes** do scan ativo e entrega dois arquivos que alimentam as etapas seguintes:

- `targets_enriched.txt` → entrada para `swarm.sh`
- `leaked_creds.csv` → entrada para `swarm_red.sh` (hydra)

---

## Fases de Execução

| # | Fase | Ferramentas |
|---|------|-------------|
| 1 | Domain Intelligence | `dig`, `whois`, crt.sh API |
| 2 | Subdomain Discovery (passivo) | `subfinder`, `amass`, `dnsx` |
| 3 | Email & Employee Harvesting | `theHarvester`, Hunter.io API |
| 4 | Historical URLs | `waybackurls`, `gau` |
| 5 | GitHub Dorking | `trufflehog`, GitHub Search API |
| 6 | Leaked Credentials | HaveIBeenPwned API v3 |
| 7 | Shodan Intelligence | Shodan API |
| 8 | Cloud Surface | S3/Azure bucket enum, subdomain takeover |
| 9 | Build Outputs | `targets_enriched.txt`, `osint_summary.json` |
| 10 | Relatório HTML | Python (embutido) |

---

## Instalação de Dependências

```bash
# Go (ProjectDiscovery)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest

# Python
pip install theHarvester

# trufflehog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Sistema
sudo apt install whois amass -y
```

---

## Uso

```bash
# Básico
bash osint.sh example.com

# Com APIs externas (recomendado)
bash osint.sh example.com \
  --shodan-key $SHODAN_KEY \
  --hibp-key $HIBP_KEY \
  --github-token $GITHUB_TOKEN

# Config persistente (evita passar keys toda execução)
cat >> ~/.osint.conf << EOF
SHODAN_API_KEY=sua_key_aqui
HIBP_API_KEY=sua_key_aqui
GITHUB_TOKEN=seu_token_aqui
HUNTER_API_KEY=sua_key_aqui
EOF

# Pular confirmação RoE (CI/CD)
bash osint.sh example.com --no-roe

# Output em diretório customizado
bash osint.sh example.com --out /opt/engagements/cliente_x/osint

# Nome de org GitHub diferente do domínio
bash osint.sh example.com --org nome-da-org-no-github
```

---

## Flags

| Flag | Descrição |
|------|-----------|
| `--shodan-key KEY` | Shodan API key (ou `SHODAN_API_KEY` no env) |
| `--hibp-key KEY` | HaveIBeenPwned API key (ou `HIBP_API_KEY`) |
| `--github-token TOKEN` | GitHub token para dorking (ou `GITHUB_TOKEN`) |
| `--hunter-key KEY` | Hunter.io API key (ou `HUNTER_API_KEY`) |
| `--org NAME` | Nome da org no GitHub (padrão: 1º segmento do domínio) |
| `--out DIR` | Diretório de output customizado |
| `--no-roe` | Pular confirmação RoE (automação/CI) |
| `--help` | Mostrar ajuda |

---

## Output

```
osint_<domain>_<timestamp>/
├── osint_report.html           # Relatório principal (dark theme)
├── osint_summary.json          # Metadados legíveis por máquina
├── targets_enriched.txt        # Alvos para swarm.sh
├── leaked_creds.csv            # Contas vazadas para swarm_red.sh
├── subdomains_passive.txt      # Subdomínios descobertos
├── subdomains_live.txt         # Subdomínios ativos (dnsx)
├── emails.txt                  # E-mails coletados
├── employees.txt               # Funcionários identificados
├── historical_urls.txt         # URLs históricas (wayback + gau)
├── interesting_endpoints.txt   # Endpoints dinâmicos/com parâmetros
├── dns_records.txt             # Registros DNS completos
├── whois.txt                   # WHOIS
├── asn_info.txt                # ASN / CIDR
├── email_security.txt          # SPF / DMARC / DKIM
├── github_leaks/
│   ├── trufflehog.json         # Segredos em repos públicos
│   └── search_dorks.json       # Resultados do GitHub Search
├── shodan/
│   ├── hostname_search.json    # Busca por hostname
│   ├── host_<ip>.json          # Detalhes por IP
│   ├── exposed_services.txt    # Serviços expostos
│   └── cves_from_shodan.txt    # CVEs identificados via Shodan
└── cloud/
    ├── buckets_found.csv       # S3/Azure buckets identificados
    └── takeover_candidates.csv # Candidatos a subdomain takeover
```

---

## Integração com SWARM

```bash
# 1. Coletar inteligência passiva
bash osint.sh target.com --shodan-key $KEY --hibp-key $KEY

# 2. Alimentar o scan ativo com os resultados
bash swarm.sh target.com --osint-dir osint_target.com_*/

# 3. Exploração com credenciais vazadas
bash swarm_red.sh -t target.com --standalone \
  --creds osint_target.com_*/leaked_creds.csv
```

---

## API Keys Necessárias (opcionais mas recomendadas)

| Serviço | Onde obter | Impacto sem a key |
|---------|-----------|-------------------|
| [Shodan](https://account.shodan.io/) | account.shodan.io | Sem dados de serviços expostos e CVEs |
| [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) | haveibeenpwned.com | Sem verificação de vazamentos |
| [GitHub](https://github.com/settings/tokens) | github.com/settings/tokens | Dorking limitado (sem Search API) |
| [Hunter.io](https://hunter.io/api) | hunter.io/api | Sem harvesting adicional de e-mails |

---

## Higiene de Dados (pós-engajamento)

```bash
tar czf osint_results.tar.gz osint_*/
gpg -c osint_results.tar.gz
shred -vfz osint_results.tar.gz
rm -rf osint_*/
```

---

## Parte do Ecossistema SWARM

| Script | Função |
|--------|--------|
| **osint.sh** | Inteligência passiva pré-engajamento |
| [swarm.sh](https://github.com/trickMeister1337/swarm) | Recon e varredura de vulnerabilidades |
| swarm_red.sh | Exploração automatizada |
| pci_scan.sh | Conformidade PCI DSS 4.0.1 |
