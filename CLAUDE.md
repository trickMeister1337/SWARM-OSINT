# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Contexto do Ambiente

Este é um ambiente de red team / pentest autorizado. Os scripts são ferramentas de segurança ofensiva para uso exclusivo em ambientes com Rules of Engagement (RoE) assinado.

---

## Scripts Principais

### `swarm.sh` — Orquestrador de Reconhecimento e Varredura
Pipeline de recon e varredura de vulnerabilidades:

1. **Fase 1** — Descoberta de subdomínios (subfinder + httpx + katana)
2. **Fase 2** — Mapeamento de endpoints
3. **Fases 3+4** — TLS (testssl.sh) + Nuclei em paralelo
4. **Fase 5** — Confirmação de exploits (poc_validator.py)
5. **Fase 7** — WAF Detection (wafw00f) + Email Security (SPF/DMARC/DKIM)
6. **Fase 9** — ZAP Spider + Active Scan
7. **Fase 10** — JS Analysis + Smuggler + ffuf + trufflehog
8. **Fase 11** — Relatório HTML

```bash
# Uso básico
bash swarm.sh <target>

# Multi-target
bash swarm.sh -f targets.txt

# Scan autenticado
bash swarm.sh <target> --token "eyJ..."

# Docker
docker run --rm -v $(pwd)/output:/swarm/output trickmeister1337/swarm https://target.com
```

Output: `scan_<domain>_<timestamp>/`

### `swarm_red.sh` — Engine de Exploração Automatizada
Consome resultados do SWARM e executa exploração (SQLi → RCE, brute force, Metasploit):

```bash
# Standalone (mais comum)
bash swarm_red.sh -t <target> --standalone -p <profile>

# Consumindo output do SWARM
bash swarm_red.sh -d ~/scan_<domain>_<timestamp>/

# Dry run (simulação sem execução real)
bash swarm_red.sh -t <target> --standalone --dry-run
```

Output: `swarm_red_<target>_<timestamp>/`

### `osint.sh` — Coleta de Inteligência Pré-Engajamento
Coleta passiva/semi-ativa executada **antes** do swarm.sh:

1. **Fase 1** — Domain Intelligence (WHOIS, DNS, crt.sh, SPF/DMARC/DKIM, ASN)
2. **Fase 2** — Subdomain Discovery passivo (subfinder + amass + crt.sh + dnsx)
3. **Fase 3** — Email & Employee Harvesting (theHarvester + Hunter.io)
4. **Fase 4** — Historical URLs (waybackurls + gau + endpoints dinâmicos)
5. **Fase 5** — GitHub Dorking (trufflehog + GitHub Search API)
6. **Fase 6** — Leaked Credentials (HaveIBeenPwned API v3)
7. **Fase 7** — Shodan Intelligence (hostname search + CVEs por IP)
8. **Fase 8** — Cloud Surface (S3/Azure buckets + subdomain takeover)
9. **Fase 9** — Build outputs para integração com swarm.sh
10. **Fase 10** — Relatório HTML

```bash
# Uso básico
bash osint.sh <target>

# Com APIs externas
bash osint.sh <target> --shodan-key $KEY --hibp-key $KEY --github-token $TOKEN

# Config persistente
echo "SHODAN_API_KEY=xxx" >> ~/.osint.conf

# Pular confirmação RoE (CI/CD)
bash osint.sh <target> --no-roe
```

Output: `osint_<domain>_<timestamp>/`

**Integração com SWARM:**
```bash
bash osint.sh target.com
bash swarm.sh target.com --osint-dir osint_target.com_*/
```

**Arquivos-chave gerados:**
- `targets_enriched.txt` — subdomínios + IPs para swarm.sh
- `leaked_creds.csv` — contas vazadas para hydra no swarm_red.sh
- `osint_summary.json` — metadados legíveis por máquina
- `osint_report.html` — relatório completo

---

### `pci_scan.sh` — Scanner de Conformidade PCI DSS 4.0.1
Cobre Req 1.3, 2.2, 3.5, 4.2.1, 6.x, 8.x, 11.x, 12.5.2. **Não substitui** ASV scan externo (Req 11.3.2) nem pentest humano (Req 11.4).

```bash
bash pci_scan.sh <target>
```

---

## Perfis de Execução (`profiles.conf`)

| Perfil | sqlmap L/R/T | Brute Force | Nikto | Uso |
|--------|-------------|-------------|-------|-----|
| `staging` | 3/2/5 | Sim | Sim | Homolog/QA |
| `lab` | 5/3/10 | Sim | Sim | Lab descartável |
| `production` | 1/1/1 | Não | Não | Prod (janela aprovada) |

---

## Módulos Python (`lib/`)

| Arquivo | Responsabilidade |
|---------|-----------------|
| `parsers.py` | Parse de Nuclei JSONL, ZAP JSON, extração de URLs e CVEs |
| `evidence.py` | Coleta e consolidação de evidências de todas as fontes |
| `report_generator.py` | Gera `relatorio_swarm_red.html` (estilo Big4) |
| `poc_validator.py` | Confirmação ativa de vulnerabilidades (min 60% confidence) |
| `cve_enricher.py` | Enriquecimento NVD/EPSS/KEV com cache diário |
| `report_gen.py` / `swarm_report.py` | Gerador de relatório para o `swarm.sh` |
| `header_check.py` | Verificação de security headers |

Os módulos Python estão **embutidos** no `swarm_red.sh` como heredocs e são extraídos automaticamente para `lib/` na primeira execução. Se o script for mais novo que `lib/parsers.py`, a lib é re-extraída.

---

## Ferramentas Externas Necessárias

**Go (ProjectDiscovery):** subfinder, httpx, nuclei, katana, ffuf  
**Sistema:** nmap, sqlmap, metasploit, hydra, nikto, zaproxy, testssl.sh  
**Python pip:** requests, wafw00f, trufflehog

Atualização:
```bash
nuclei -update && nuclei -update-templates
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

---

## Estrutura de Output do SWARM RED

```
swarm_red_<target>_<timestamp>/
├── relatorio_swarm_red.html    # Relatório principal
├── exploits_confirmed.csv      # 10 colunas: URL,Severity,Tool,Status,DB_Type,...
├── false_positives.csv
├── evidence/
│   └── evidence_NNN.txt        # Evidência estruturada por exploit
├── sqlmap/<hash>/log
├── metasploit/swarm_red.rc
└── swarm_red.log
```

Um exploit é **CONFIRMADO** somente se tiver: databases enumeradas + tabelas enumeradas + dump_count > 0 + payload capturado.

---

## Critérios de Confirmação de PoC (`poc_validator.py`)

- Threshold mínimo: 60% de confidence (`MIN_CONFIRM_CONFIDENCE`)
- Padrões externos em `vuln_patterns.json`
- Lê também alertas ZAP do XML, testssl, e resultados de email security (SPF/DMARC/DKIM)

---

## Validação de Sintaxe

```bash
# Verificar sintaxe dos scripts bash
bash -n swarm.sh
bash -n swarm_red.sh
bash -n pci_scan.sh

# Verificar versão do swarm_red
grep VERSION swarm_red.sh

# Testar extração de lib
bash swarm_red.sh --help
```

---

## Pós-Scan (Higiene de Dados)

```bash
tar czf results.tar.gz swarm_red_*/
gpg -c results.tar.gz
shred -vfz results.tar.gz
rm -rf swarm_red_*/
```
