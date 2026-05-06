#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  SWARM OSINT — Pre-Engagement Intelligence Collector
# ═══════════════════════════════════════════════════════════════════════════════
#  Coleta inteligência passiva antes do engajamento ativo (swarm.sh).
#
#  Pipeline:  SWARM OSINT (inteligência passiva) → SWARM (recon ativo)
#
#  USO EXCLUSIVO EM AMBIENTES AUTORIZADOS E CONTROLADOS.
#  Requer: Rules of Engagement (RoE) assinado + domínio no escopo.
#
#  Uso:
#    bash osint.sh <target>
#    bash osint.sh <target> --shodan-key KEY --hibp-key KEY --github-token TOKEN
#    bash osint.sh <target> --out /path/dir
#    bash osint.sh <target> --no-roe
#
#  Integração com SWARM:
#    bash osint.sh target.com
#    bash swarm.sh target.com --osint-dir osint_target.com_<timestamp>/
#
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

readonly VERSION="1.0.0"
readonly SCRIPT_START=$(date +%s)

# ─── PATH ────────────────────────────────────────────────────────────────────
for _d in "$HOME/go/bin" "/root/go/bin" "$HOME/.local/bin" \
           "/usr/local/go/bin" "/opt/go/bin" "/usr/local/bin" "/snap/bin"; do
    [ -d "$_d" ] && [[ ":$PATH:" != *":$_d:"* ]] && export PATH="$PATH:$_d"
done
unset _d

# ─── Cores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'
MAG='\033[0;35m'; BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# ─── Signal handling ─────────────────────────────────────────────────────────
ABORT=false
CHILD_PIDS=()

_cleanup_and_exit() {
    ABORT=true
    echo ""
    echo -e "  ${RED}${BLD}╔══════════════════════════════════════════════════════════╗${RST}"
    echo -e "  ${RED}${BLD}║           ⚠  ABORTADO PELO OPERADOR (Ctrl+C)           ║${RST}"
    echo -e "  ${RED}${BLD}╚══════════════════════════════════════════════════════════╝${RST}"
    echo ""
    for pid in "${CHILD_PIDS[@]:-}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    [ -n "${OUTDIR:-}" ] && [ -d "${OUTDIR:-}" ] && \
        echo -e "  ${CYN}Output parcial:${RST} $OUTDIR/"
    echo -e "  ${DIM}Duração: $(elapsed)${RST}"
    exit 130
}
trap _cleanup_and_exit INT TERM

# ─── Variáveis globais ───────────────────────────────────────────────────────
TARGET=""
DOMAIN=""
BASE_DOMAIN=""
ORG_NAME=""
OUTDIR=""
LOGFILE="/dev/null"
SHODAN_KEY=""
HIBP_KEY=""
GITHUB_TOKEN=""
HUNTER_KEY=""
SKIP_ROE=false
CONF_FILE="$HOME/.osint.conf"
declare -a MAIN_IPS=()

# Contadores
SUBDOMAINS_FOUND=0
EMAILS_FOUND=0
URLS_FOUND=0
LEAKS_FOUND=0
BUCKETS_FOUND=0

# ═══════════════════════════════════════════════════════════════════════════════
#  FUNÇÕES UTILITÁRIAS
# ═══════════════════════════════════════════════════════════════════════════════
elapsed() {
    local end; end=$(date +%s)
    local dur=$((end - SCRIPT_START))
    printf '%02d:%02d:%02d' $((dur/3600)) $(((dur%3600)/60)) $((dur%60))
}

phase()  {
    echo -e "\n${CYN}════════════════════════════════════════════════════════════════${RST}" | tee -a "$LOGFILE"
    echo -e "  ${CYN}${BLD}$*${RST}" | tee -a "$LOGFILE"
    echo -e "${CYN}════════════════════════════════════════════════════════════════${RST}" | tee -a "$LOGFILE"
}
info()   { echo -e "  ${GRN}[✓]${RST} $*" | tee -a "$LOGFILE"; }
warn()   { echo -e "  ${YLW}[!]${RST} $*" | tee -a "$LOGFILE"; }
fail()   { echo -e "  ${RED}[✗]${RST} $*" | tee -a "$LOGFILE"; }
step()   { echo -e "  ${BLD}[→]${RST} $*" | tee -a "$LOGFILE"; }
has()    { command -v "$1" &>/dev/null; }
ts()     { date '+%Y-%m-%d %H:%M:%S'; }

# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════════════
banner() {
    echo -e "${CYN}"
    cat << 'BANNER'
   _____ _       _____    ____  __  ___    ____  _____ _____   ___________
  / ___/| |     / /   |  / __ \/  |/  /   / __ \/ ___//  _/  /_  __/  _/
  \__ \ | | /| / / /| | / /_/ / /|_/ /   / / / /\__ \ / /     / /  / /
 ___/ / | |/ |/ / ___ |/ _, _/ /  / /   / /_/ /___/ // /      / / _/ /
/____/  |__/|__/_/  |_/_/ |_/_/  /_/    \____//____/___/     /_/ /___/
BANNER
    echo -e "${RST}"
    echo -e "  ${DIM}v${VERSION} — Pre-Engagement Intelligence Collector${RST}"
    echo -e "  ${YLW}⚑  USO EXCLUSIVO EM AMBIENTES COM RoE ASSINADO${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  USO / HELP
# ═══════════════════════════════════════════════════════════════════════════════
usage() {
    echo -e "${BLD}Uso:${RST}  bash osint.sh <target> [opções]"
    echo ""
    echo -e "${BLD}Exemplos:${RST}"
    echo -e "  bash osint.sh example.com"
    echo -e "  bash osint.sh example.com --shodan-key \$SHODAN_KEY --hibp-key \$HIBP_KEY"
    echo -e "  bash osint.sh example.com --github-token \$GH_TOKEN --no-roe"
    echo ""
    echo -e "${BLD}Opções:${RST}"
    echo -e "  --shodan-key KEY      Shodan API key  (ou SHODAN_API_KEY no env)"
    echo -e "  --hibp-key   KEY      HIBP API key    (ou HIBP_API_KEY no env)"
    echo -e "  --github-token TOKEN  GitHub token    (ou GITHUB_TOKEN no env)"
    echo -e "  --hunter-key KEY      Hunter.io key   (ou HUNTER_API_KEY no env)"
    echo -e "  --org NAME            Nome da org no GitHub (padrão: 1º segmento do domínio)"
    echo -e "  --out DIR             Diretório de output customizado"
    echo -e "  --no-roe              Pular confirmação RoE (CI/CD)"
    echo -e "  --help, -h            Mostrar este help"
    echo ""
    echo -e "${BLD}Config file:${RST}  ~/.osint.conf"
    echo -e "  SHODAN_API_KEY=xxx"
    echo -e "  HIBP_API_KEY=xxx"
    echo -e "  GITHUB_TOKEN=xxx"
    echo -e "  HUNTER_API_KEY=xxx"
    echo ""
    echo -e "${BLD}Integração SWARM:${RST}"
    echo -e "  bash osint.sh target.com"
    echo -e "  bash swarm.sh target.com --osint-dir osint_target.com_*/   ${DIM}# próxima versão${RST}"
    echo ""
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PARSE DE ARGUMENTOS
# ═══════════════════════════════════════════════════════════════════════════════
parse_args() {
    [ $# -eq 0 ] && usage

    # Config file
    if [ -f "$CONF_FILE" ]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE" 2>/dev/null || true
    fi

    # Variáveis de ambiente (prioridade sobre config file)
    SHODAN_KEY="${SHODAN_API_KEY:-${SHODAN_KEY:-}}"
    HIBP_KEY="${HIBP_API_KEY:-${HIBP_KEY:-}}"
    GITHUB_TOKEN="${GITHUB_TOKEN:-}"
    HUNTER_KEY="${HUNTER_API_KEY:-${HUNTER_KEY:-}}"

    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h)         usage ;;
            --no-roe)          SKIP_ROE=true ;;
            --shodan-key)      SHODAN_KEY="$2"; shift ;;
            --hibp-key)        HIBP_KEY="$2"; shift ;;
            --github-token)    GITHUB_TOKEN="$2"; shift ;;
            --hunter-key)      HUNTER_KEY="$2"; shift ;;
            --out)             OUTDIR="$2"; shift ;;
            --org)             ORG_NAME="$2"; shift ;;
            --*)               warn "Flag desconhecida: $1 (ignorada)" ;;
            *)
                [ -z "$TARGET" ] && TARGET="$1"
                ;;
        esac
        shift
    done

    [ -z "$TARGET" ] && { fail "Alvo não especificado."; usage; }

    # Domínio limpo (sem esquema, www, path)
    DOMAIN=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|^www\.||')
    BASE_DOMAIN=$(echo "$DOMAIN" | awk -F. '{if(NF>=2) print $(NF-1)"."$NF; else print $0}')

    [ -z "$ORG_NAME" ] && ORG_NAME=$(echo "$DOMAIN" | cut -d. -f1)
}

# ═══════════════════════════════════════════════════════════════════════════════
#  VALIDAÇÃO DE FERRAMENTAS
# ═══════════════════════════════════════════════════════════════════════════════
validate_tools() {
    phase "VALIDAÇÃO DE FERRAMENTAS"

    local required=(curl dig python3)
    local optional=(whois subfinder amass dnsx theHarvester waybackurls gau trufflehog jq)
    local missing_req=0

    for tool in "${required[@]}"; do
        if has "$tool"; then
            info "$tool → $(command -v "$tool")"
        else
            fail "$tool NÃO ENCONTRADO (obrigatório)"
            missing_req=$((missing_req + 1))
        fi
    done

    for tool in "${optional[@]}"; do
        if has "$tool"; then
            info "$tool → $(command -v "$tool")"
        else
            warn "$tool não encontrado — fase correspondente será ignorada"
        fi
    done

    echo ""
    [ -n "$SHODAN_KEY" ]   && info "Shodan API key   → configurada" || warn "Shodan API key   → não configurada (fase ignorada)"
    [ -n "$HIBP_KEY" ]     && info "HIBP API key     → configurada" || warn "HIBP API key     → não configurada (fase ignorada)"
    [ -n "$GITHUB_TOKEN" ] && info "GitHub token     → configurado" || warn "GitHub token     → não configurado (dorking limitado)"
    [ -n "$HUNTER_KEY" ]   && info "Hunter.io key    → configurada" || true

    [ "$missing_req" -gt 0 ] && { fail "Ferramentas obrigatórias ausentes. Abortando."; exit 1; }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIRMAÇÃO ROE
# ═══════════════════════════════════════════════════════════════════════════════
confirm_roe() {
    [ "$SKIP_ROE" = true ] && return 0

    local domain_padded
    domain_padded=$(printf '%-40s' "$DOMAIN")

    echo ""
    echo -e "  ${YLW}${BLD}╔══════════════════════════════════════════════════════════╗${RST}"
    echo -e "  ${YLW}${BLD}║             ⚠  CONFIRMAÇÃO DE ESCOPO  ⚠                ║${RST}"
    echo -e "  ${YLW}${BLD}╠══════════════════════════════════════════════════════════╣${RST}"
    echo -e "  ${YLW}${BLD}║                                                        ║${RST}"
    echo -e "  ${YLW}${BLD}║  SWARM OSINT executa coleta PASSIVA/SEMI-ATIVA:        ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Consultas DNS, WHOIS, crt.sh                        ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Enumeração passiva de subdomínios                   ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Harvesting de e-mails e funcionários                ║${RST}"
    echo -e "  ${YLW}${BLD}║  • URLs históricas (Wayback Machine / GAU)             ║${RST}"
    echo -e "  ${YLW}${BLD}║  • GitHub dorking em repositórios públicos             ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Verificação de vazamentos (HIBP)                    ║${RST}"
    echo -e "  ${YLW}${BLD}║  • Enumeração de buckets S3/Azure (nomes derivados)    ║${RST}"
    echo -e "  ${YLW}${BLD}║                                                        ║${RST}"
    echo -e "  ${YLW}${BLD}║  Domínio: ${domain_padded}  ║${RST}"
    echo -e "  ${YLW}${BLD}║                                                        ║${RST}"
    echo -e "  ${YLW}${BLD}║  USO SEM AUTORIZAÇÃO É CRIME (Art. 154-A CP).         ║${RST}"
    echo -e "  ${YLW}${BLD}╚══════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  ${BLD}Confirme digitando exatamente:${RST} ${YLW}EU AUTORIZO${RST}"

    local confirmation
    if [ -t 0 ]; then
        read -rp "  > " confirmation < /dev/tty
    else
        read -rp "  > " confirmation
    fi

    if [ "$confirmation" != "EU AUTORIZO" ]; then
        fail "Confirmação inválida. Abortando."
        exit 1
    fi

    info "Autorização confirmada em $(ts)"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SETUP DO DIRETÓRIO DE OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════
setup_output() {
    local ts_dir
    ts_dir=$(date +%Y%m%d_%H%M%S)

    [ -z "$OUTDIR" ] && OUTDIR="$(pwd)/osint_${DOMAIN}_${ts_dir}"

    mkdir -p "$OUTDIR/github_leaks" "$OUTDIR/shodan" "$OUTDIR/cloud"
    LOGFILE="$OUTDIR/osint.log"
    touch "$LOGFILE"

    echo "[$(ts)] SWARM OSINT v${VERSION} iniciado" >> "$LOGFILE"
    echo "[$(ts)] Alvo: $DOMAIN | Base: $BASE_DOMAIN" >> "$LOGFILE"
    echo "[$(ts)] Output: $OUTDIR" >> "$LOGFILE"

    echo ""
    info "Output: ${BLD}$OUTDIR${RST}"
    info "Log:    $LOGFILE"
    info "Alvo:   ${BLD}$DOMAIN${RST}  (base: $BASE_DOMAIN)"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 1 — DOMAIN INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════
phase_domain_intel() {
    phase "FASE 1 — DOMAIN INTELLIGENCE"
    [ "$ABORT" = true ] && return 130

    # WHOIS
    step "WHOIS"
    if has whois; then
        timeout 30 whois "$DOMAIN" > "$OUTDIR/whois.txt" 2>/dev/null || true
        info "WHOIS → whois.txt"
    else
        warn "whois não disponível"
    fi

    # DNS Records
    step "DNS Records (A, AAAA, MX, TXT, NS, SOA)"
    {
        for rtype in A AAAA MX TXT NS SOA; do
            echo "=== $rtype ==="
            dig "$rtype" "$DOMAIN" +noall +answer +ttlunits 2>/dev/null
            echo ""
        done
    } > "$OUTDIR/dns_records.txt" 2>/dev/null
    info "DNS records → dns_records.txt"

    # IPs do domínio (globais para fases seguintes)
    mapfile -t MAIN_IPS < <(dig A "$DOMAIN" +short 2>/dev/null | grep -E '^[0-9]+\.' || true)
    if [ ${#MAIN_IPS[@]} -gt 0 ]; then
        printf '%s\n' "${MAIN_IPS[@]}" > "$OUTDIR/main_ips.txt"
        info "IPs resolvidos: ${MAIN_IPS[*]}"
    fi

    # ASN lookup via Team Cymru
    step "ASN / CIDR lookup (Team Cymru)"
    {
        echo "IP | ASN | Prefix | Country | Registry | Organization"
        for ip in "${MAIN_IPS[@]:-}"; do
            [ -z "$ip" ] && continue
            local result
            result=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | tail -1)
            echo "$ip | $result"
        done
    } > "$OUTDIR/asn_info.txt" 2>/dev/null
    info "ASN info → asn_info.txt"

    # Certificate Transparency (crt.sh)
    step "Certificate Transparency (crt.sh)"
    local crt_raw
    crt_raw=$(curl -s --max-time 30 "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null)
    if [ -n "$crt_raw" ] && echo "$crt_raw" | python3 -c "import sys,json; json.load(sys.stdin)" &>/dev/null; then
        echo "$crt_raw" | python3 -c "
import sys, json
data = json.load(sys.stdin)
names = set()
for r in data:
    for name in r.get('name_value','').split('\n'):
        name = name.strip().lstrip('*.')
        if name:
            names.add(name)
for n in sorted(names):
    print(n)
" > "$OUTDIR/crtsh_subdomains.txt" 2>/dev/null || touch "$OUTDIR/crtsh_subdomains.txt"
        local crt_count
        crt_count=$(wc -l < "$OUTDIR/crtsh_subdomains.txt" 2>/dev/null || echo 0)
        info "crt.sh → ${crt_count} nomes de certificados"
    else
        warn "crt.sh: sem resultado ou API indisponível"
        touch "$OUTDIR/crtsh_subdomains.txt"
    fi

    # Email Security Records
    step "Email Security Records (SPF/DMARC/MX)"
    {
        echo "=== SPF ==="
        dig TXT "$DOMAIN" +short 2>/dev/null | grep -i "v=spf" || echo "(não encontrado)"
        echo ""
        echo "=== DMARC ==="
        dig TXT "_dmarc.$DOMAIN" +short 2>/dev/null || echo "(não encontrado)"
        echo ""
        echo "=== DKIM (common selectors) ==="
        for sel in default google selector1 selector2 k1 mail; do
            result=$(dig TXT "${sel}._domainkey.$DOMAIN" +short 2>/dev/null)
            [ -n "$result" ] && echo "selector=$sel: $result"
        done
        echo ""
        echo "=== MX ==="
        dig MX "$DOMAIN" +short 2>/dev/null || echo "(não encontrado)"
    } > "$OUTDIR/email_security.txt" 2>/dev/null
    info "Email security → email_security.txt"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 2 — SUBDOMAIN DISCOVERY (PASSIVO)
# ═══════════════════════════════════════════════════════════════════════════════
phase_subdomain_discovery() {
    phase "FASE 2 — SUBDOMAIN DISCOVERY (PASSIVO)"
    [ "$ABORT" = true ] && return 130

    local sources=()

    # subfinder
    if has subfinder; then
        step "subfinder (modo passivo)"
        timeout 120 subfinder -d "$DOMAIN" -silent -all 2>/dev/null \
            > "$OUTDIR/subfinder.txt" || true
        local sf_count
        sf_count=$(wc -l < "$OUTDIR/subfinder.txt" 2>/dev/null || echo 0)
        info "subfinder → ${sf_count} subdomínios"
        sources+=("$OUTDIR/subfinder.txt")
    else
        warn "subfinder não disponível"
    fi

    # amass passive
    if has amass; then
        step "amass (modo passivo)"
        timeout 180 amass enum -passive -d "$DOMAIN" \
            -o "$OUTDIR/amass.txt" 2>/dev/null || true
        local am_count
        am_count=$(wc -l < "$OUTDIR/amass.txt" 2>/dev/null || echo 0)
        info "amass → ${am_count} subdomínios"
        sources+=("$OUTDIR/amass.txt")
    else
        warn "amass não disponível"
    fi

    # Adicionar crt.sh da fase anterior
    [ -f "$OUTDIR/crtsh_subdomains.txt" ] && sources+=("$OUTDIR/crtsh_subdomains.txt")

    # Consolidar
    if [ ${#sources[@]} -gt 0 ]; then
        sort -u "${sources[@]}" 2>/dev/null \
            | grep -vE '^\*' \
            > "$OUTDIR/subdomains_passive.txt" 2>/dev/null || true
    else
        touch "$OUTDIR/subdomains_passive.txt"
    fi

    SUBDOMAINS_FOUND=$(wc -l < "$OUTDIR/subdomains_passive.txt" 2>/dev/null || echo 0)
    info "Total subdomínios únicos → ${SUBDOMAINS_FOUND}"

    # dnsx — quais estão vivos
    if has dnsx; then
        step "dnsx — resolução de subdomínios ativos"
        timeout 120 dnsx \
            -l "$OUTDIR/subdomains_passive.txt" \
            -silent -resp -a -cname \
            > "$OUTDIR/subdomains_live.txt" 2>/dev/null || true
        local live_count
        live_count=$(wc -l < "$OUTDIR/subdomains_live.txt" 2>/dev/null || echo 0)
        info "Subdomínios ativos → ${live_count}"
    else
        cp "$OUTDIR/subdomains_passive.txt" "$OUTDIR/subdomains_live.txt" 2>/dev/null || true
        warn "dnsx não disponível — todos os subdomínios tratados como ativos"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 3 — EMAIL & EMPLOYEE HARVESTING
# ═══════════════════════════════════════════════════════════════════════════════
phase_email_harvesting() {
    phase "FASE 3 — EMAIL & EMPLOYEE HARVESTING"
    [ "$ABORT" = true ] && return 130

    # theHarvester
    if has theHarvester; then
        step "theHarvester (Google, Bing, LinkedIn, Yahoo)"
        timeout 300 theHarvester \
            -d "$DOMAIN" \
            -b google,bing,linkedin,yahoo \
            -f "$OUTDIR/theharvester" 2>/dev/null || true
        info "theHarvester → theharvester.json"
    else
        warn "theHarvester não disponível"
    fi

    # Hunter.io API
    if [ -n "$HUNTER_KEY" ]; then
        step "Hunter.io — email discovery"
        local hunter_raw
        hunter_raw=$(curl -s --max-time 30 \
            "https://api.hunter.io/v2/domain-search?domain=${DOMAIN}&api_key=${HUNTER_KEY}" \
            2>/dev/null)
        if [ -n "$hunter_raw" ]; then
            echo "$hunter_raw" > "$OUTDIR/hunter_results.json"
            echo "$hunter_raw" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for e in data.get('data', {}).get('emails', []):
    v = e.get('value', '')
    if v:
        print(v)
" 2>/dev/null > "$OUTDIR/emails_hunter.txt" || true
            local h_count
            h_count=$(wc -l < "$OUTDIR/emails_hunter.txt" 2>/dev/null || echo 0)
            info "Hunter.io → ${h_count} e-mails"
        fi
    else
        warn "Hunter.io key não configurada"
    fi

    # Consolidar todos os e-mails
    {
        # theHarvester JSON
        if [ -f "$OUTDIR/theharvester.json" ]; then
            python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/theharvester.json'))
    for e in data.get('emails', []):
        print(e)
except:
    pass
" 2>/dev/null || true
        fi
        # Hunter.io
        cat "$OUTDIR/emails_hunter.txt" 2>/dev/null || true
    } | grep -iE "^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$" \
      | sort -u > "$OUTDIR/emails.txt" 2>/dev/null || true

    EMAILS_FOUND=$(wc -l < "$OUTDIR/emails.txt" 2>/dev/null || echo 0)
    info "Total e-mails únicos → ${EMAILS_FOUND}"

    # Funcionários do theHarvester
    if [ -f "$OUTDIR/theharvester.json" ]; then
        python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/theharvester.json'))
    for p in data.get('linkedin_people', []):
        print(p)
except:
    pass
" 2>/dev/null > "$OUTDIR/employees.txt" || true
        local emp_count
        emp_count=$(wc -l < "$OUTDIR/employees.txt" 2>/dev/null || echo 0)
        [ "$emp_count" -gt 0 ] && info "Funcionários identificados → ${emp_count}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 4 — HISTORICAL URLS
# ═══════════════════════════════════════════════════════════════════════════════
phase_historical_urls() {
    phase "FASE 4 — HISTORICAL URLS (Wayback / GAU)"
    [ "$ABORT" = true ] && return 130

    local url_sources=()

    # waybackurls
    if has waybackurls; then
        step "waybackurls — Wayback Machine"
        echo "$DOMAIN" | timeout 180 waybackurls 2>/dev/null \
            > "$OUTDIR/waybackurls.txt" || true
        local wb_count
        wb_count=$(wc -l < "$OUTDIR/waybackurls.txt" 2>/dev/null || echo 0)
        info "waybackurls → ${wb_count} URLs"
        url_sources+=("$OUTDIR/waybackurls.txt")
    else
        warn "waybackurls não disponível"
    fi

    # gau
    if has gau; then
        step "gau — GetAllURLs (inclui subdomínios)"
        echo "$DOMAIN" | timeout 180 gau --subs 2>/dev/null \
            > "$OUTDIR/gau_urls.txt" || true
        local gau_count
        gau_count=$(wc -l < "$OUTDIR/gau_urls.txt" 2>/dev/null || echo 0)
        info "gau → ${gau_count} URLs"
        url_sources+=("$OUTDIR/gau_urls.txt")
    else
        warn "gau não disponível"
    fi

    if [ ${#url_sources[@]} -gt 0 ]; then
        sort -u "${url_sources[@]}" 2>/dev/null > "$OUTDIR/historical_urls.txt" || true
        URLS_FOUND=$(wc -l < "$OUTDIR/historical_urls.txt" 2>/dev/null || echo 0)
        info "Total URLs históricas únicas → ${URLS_FOUND}"

        # Endpoints com parâmetros ou arquivos dinâmicos
        {
            grep -E '\.(php|asp|aspx|jsp|do|action|cgi)(\?|$)' "$OUTDIR/historical_urls.txt" 2>/dev/null || true
            grep -E '\?[a-zA-Z].*=' "$OUTDIR/historical_urls.txt" 2>/dev/null || true
        } | sort -u > "$OUTDIR/interesting_endpoints.txt" 2>/dev/null || true
        local ep_count
        ep_count=$(wc -l < "$OUTDIR/interesting_endpoints.txt" 2>/dev/null || echo 0)
        info "Endpoints dinâmicos/com parâmetros → ${ep_count}"
    else
        warn "Nenhuma ferramenta de URL histórica disponível"
        touch "$OUTDIR/historical_urls.txt" "$OUTDIR/interesting_endpoints.txt"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 5 — GITHUB DORKING
# ═══════════════════════════════════════════════════════════════════════════════
phase_github_dorking() {
    phase "FASE 5 — GITHUB DORKING"
    [ "$ABORT" = true ] && return 130

    local leaks_found=0

    # trufflehog — repos públicos da org
    if has trufflehog; then
        step "trufflehog — org: ${ORG_NAME}"
        local th_args=(github --org="$ORG_NAME" --json --no-update)
        [ -n "$GITHUB_TOKEN" ] && th_args+=(--token="$GITHUB_TOKEN")

        timeout 300 trufflehog "${th_args[@]}" \
            2>/dev/null > "$OUTDIR/github_leaks/trufflehog.json" || true

        leaks_found=$(grep -c '"SourceMetadata"' "$OUTDIR/github_leaks/trufflehog.json" 2>/dev/null || echo 0)
        if [ "$leaks_found" -gt 0 ]; then
            warn "trufflehog → ${leaks_found} segredos potenciais encontrados!"
        else
            info "trufflehog → nenhum segredo em repos públicos"
        fi
    else
        warn "trufflehog não disponível"
    fi

    # GitHub Search API — dorks
    if [ -n "$GITHUB_TOKEN" ]; then
        step "GitHub Search API — dorks de segredos"
        local dorks=(
            "\"$DOMAIN\" password"
            "\"$DOMAIN\" secret"
            "\"$DOMAIN\" api_key"
            "\"$DOMAIN\" token"
            "\"$BASE_DOMAIN\" db_password"
            "\"$BASE_DOMAIN\" connectionstring"
        )
        local dork_total=0

        for dork in "${dorks[@]}"; do
            [ "$ABORT" = true ] && break
            local encoded
            encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${dork}'))" 2>/dev/null || echo "$dork")
            local result
            result=$(curl -s --max-time 10 \
                -H "Authorization: token ${GITHUB_TOKEN}" \
                -H "Accept: application/vnd.github.v3+json" \
                "https://api.github.com/search/code?q=${encoded}&per_page=5" \
                2>/dev/null)
            local count
            count=$(echo "$result" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('total_count', 0))
except:
    print(0)
" 2>/dev/null || echo 0)
            if [ "$count" -gt 0 ]; then
                echo "$result" >> "$OUTDIR/github_leaks/search_dorks.json"
                dork_total=$((dork_total + count))
                warn "Dork '${dork}' → ${count} resultados"
            fi
            sleep 2  # rate limit GitHub API
        done

        [ "$dork_total" -gt 0 ] && \
            warn "GitHub Search → ${dork_total} resultados totais nos dorks" || \
            info "GitHub Search → sem resultados relevantes"
        leaks_found=$((leaks_found + dork_total))
    else
        warn "GitHub token não configurado — dorking via API ignorado"
    fi

    LEAKS_FOUND=$((LEAKS_FOUND + leaks_found))
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 6 — LEAKED CREDENTIALS (HaveIBeenPwned)
# ═══════════════════════════════════════════════════════════════════════════════
phase_leaked_creds() {
    phase "FASE 6 — LEAKED CREDENTIALS (HaveIBeenPwned)"
    [ "$ABORT" = true ] && return 130

    echo "email,domain,breach_name,breach_date,data_classes,source" \
        > "$OUTDIR/leaked_creds.csv"

    if [ -z "$HIBP_KEY" ]; then
        warn "HIBP API key não configurada — fase ignorada"
        warn "Configure: --hibp-key KEY  ou  HIBP_API_KEY=KEY em ~/.osint.conf"
        return 0
    fi

    local email_count
    email_count=$(wc -l < "$OUTDIR/emails.txt" 2>/dev/null || echo 0)

    if [ "$email_count" -eq 0 ]; then
        warn "Nenhum e-mail coletado — HIBP check ignorado"
        return 0
    fi

    step "HIBP v3 — verificando ${email_count} e-mails"

    local checked=0 breached=0
    while IFS= read -r email; do
        [ -z "$email" ] && continue
        [ "$ABORT" = true ] && break

        local result
        result=$(curl -s --max-time 10 \
            -H "hibp-api-key: ${HIBP_KEY}" \
            -H "User-Agent: SWARM-OSINT/${VERSION}" \
            "https://haveibeenpwned.com/api/v3/breachedaccount/${email}" \
            2>/dev/null)

        if [ -n "$result" ] && echo "$result" | python3 -c "import sys,json; json.load(sys.stdin)" &>/dev/null; then
            echo "$result" | python3 << PYEOF
import sys, json
email = "$email"
domain = "$DOMAIN"
data = json.load(sys.stdin)
for breach in data:
    name    = breach.get('Name','')
    date    = breach.get('BreachDate','')
    classes = '|'.join(breach.get('DataClasses',[]))
    print(f"{email},{domain},{name},{date},{classes},HIBP")
PYEOF
        fi >> "$OUTDIR/leaked_creds.csv" 2>/dev/null || true

        checked=$((checked + 1))
        sleep 1.5  # rate limit HIBP API v3
    done < "$OUTDIR/emails.txt"

    breached=$(( $(wc -l < "$OUTDIR/leaked_creds.csv") - 1 ))
    [ "$breached" -lt 0 ] && breached=0
    LEAKS_FOUND=$((LEAKS_FOUND + breached))
    info "HIBP → ${checked} verificados, ${breached} em vazamentos"
    info "Resultado → leaked_creds.csv"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 7 — SHODAN INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════
phase_shodan() {
    phase "FASE 7 — SHODAN INTELLIGENCE"
    [ "$ABORT" = true ] && return 130

    if [ -z "$SHODAN_KEY" ]; then
        warn "Shodan API key não configurada — fase ignorada"
        return 0
    fi

    # Busca por hostname
    step "Shodan hostname search: $DOMAIN"
    local shodan_search
    shodan_search=$(curl -s --max-time 30 \
        "https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=hostname:${DOMAIN}&facets=port,country,org" \
        2>/dev/null)

    if [ -n "$shodan_search" ]; then
        echo "$shodan_search" > "$OUTDIR/shodan/hostname_search.json"
        local total
        total=$(echo "$shodan_search" | python3 -c "
import sys,json
try:
    print(json.load(sys.stdin).get('total', 0))
except:
    print(0)
" 2>/dev/null || echo 0)
        info "Shodan hostname → ${total} resultados"

        # Extrair serviços expostos
        echo "$shodan_search" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for m in data.get('matches', []):
        ip   = m.get('ip_str','')
        port = m.get('port','')
        org  = m.get('org','')
        prod = m.get('product','')
        print(f'{ip}:{port} | {org} | {prod}')
except:
    pass
" 2>/dev/null > "$OUTDIR/shodan/exposed_services.txt" || true
        info "Serviços expostos → shodan/exposed_services.txt"
    fi

    # Detalhes por IP + CVEs
    for ip in "${MAIN_IPS[@]:-}"; do
        [ -z "$ip" ] && continue
        [ "$ABORT" = true ] && break
        step "Shodan host detail: $ip"
        local host_raw
        host_raw=$(curl -s --max-time 20 \
            "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_KEY}" 2>/dev/null)
        if [ -n "$host_raw" ]; then
            echo "$host_raw" > "$OUTDIR/shodan/host_${ip//./_}.json"
            echo "$host_raw" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for cve, d in data.get('vulns', {}).items():
        cvss    = d.get('cvss', 'N/A')
        summary = d.get('summary', '')[:80]
        print(f'{cve} (CVSS:{cvss}) — {summary}')
except:
    pass
" 2>/dev/null >> "$OUTDIR/shodan/cves_from_shodan.txt" || true
        fi
        sleep 1
    done

    local cve_count
    cve_count=$(wc -l < "$OUTDIR/shodan/cves_from_shodan.txt" 2>/dev/null || echo 0)
    [ "$cve_count" -gt 0 ] && \
        warn "CVEs via Shodan → ${cve_count}" || \
        info "CVEs via Shodan → nenhum identificado"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 8 — CLOUD SURFACE
# ═══════════════════════════════════════════════════════════════════════════════
phase_cloud_surface() {
    phase "FASE 8 — CLOUD SURFACE"
    [ "$ABORT" = true ] && return 130

    local base
    base=$(echo "$BASE_DOMAIN" | cut -d. -f1)

    local bucket_names=(
        "$base" "$DOMAIN" "${DOMAIN//./-}"
        "www-$base" "$base-backup" "$base-backups"
        "$base-assets" "$base-static" "$base-uploads"
        "$base-media" "$base-cdn" "$base-dev"
        "$base-staging" "$base-prod" "$base-logs"
        "$base-data" "$base-files" "$base-images"
        "$base-public" "$base-private"
    )

    echo "bucket_name,cloud,status,url" > "$OUTDIR/cloud/buckets_found.csv"

    # S3
    step "S3 — verificando ${#bucket_names[@]} nomes derivados"
    for bucket in "${bucket_names[@]}"; do
        [ "$ABORT" = true ] && break
        local url="https://${bucket}.s3.amazonaws.com/"
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
        case "$code" in
            200)
                warn "S3 ABERTO (listagem pública): $url"
                echo "$bucket,S3,OPEN,$url" >> "$OUTDIR/cloud/buckets_found.csv"
                BUCKETS_FOUND=$((BUCKETS_FOUND + 1))
                ;;
            403)
                info "S3 EXISTS (privado): $bucket"
                echo "$bucket,S3,EXISTS-PRIVATE,$url" >> "$OUTDIR/cloud/buckets_found.csv"
                BUCKETS_FOUND=$((BUCKETS_FOUND + 1))
                ;;
        esac
    done

    # Azure Blob
    step "Azure Blob — verificando nomes derivados"
    for bucket in "${bucket_names[@]}"; do
        [ "$ABORT" = true ] && break
        local url="https://${bucket}.blob.core.windows.net/"
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
        case "$code" in
            200|400)
                info "Azure Blob EXISTS: $bucket (HTTP $code)"
                echo "$bucket,Azure,EXISTS,$url" >> "$OUTDIR/cloud/buckets_found.csv"
                BUCKETS_FOUND=$((BUCKETS_FOUND + 1))
                ;;
        esac
    done

    # Subdomain Takeover — CNAMEs para serviços cloud mortos
    step "Subdomain takeover — verificando CNAMEs"
    local takeover_services=(
        "s3.amazonaws.com" "s3-website" "cloudfront.net"
        "azurewebsites.net" "azure-api.net" "blob.core.windows.net"
        "github.io" "herokuapp.com" "fastly.net"
        "shopify.com" "zendesk.com" "pantheonsite.io"
        "ghost.io" "netlify.app" "netlify.com"
        "bitbucket.io" "helpscoutdocs.com"
    )

    echo "subdomain,cname,service,status" > "$OUTDIR/cloud/takeover_candidates.csv"
    local takeover_count=0

    while IFS= read -r subdomain; do
        [ -z "$subdomain" ] && continue
        [ "$ABORT" = true ] && break
        # dnsx pode retornar "sub.domain.com [1.2.3.4]" — pegar só o hostname
        subdomain=$(echo "$subdomain" | awk '{print $1}')
        local cname
        cname=$(dig CNAME "$subdomain" +short 2>/dev/null | tr -d '.')

        for svc in "${takeover_services[@]}"; do
            if echo "$cname" | grep -qi "$svc"; then
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "https://$subdomain" 2>/dev/null || echo "000")
                case "$code" in
                    404|410|422)
                        warn "Possível takeover: $subdomain → $cname [$svc] (HTTP $code)"
                        echo "$subdomain,$cname,$svc,POSSIBLE" >> "$OUTDIR/cloud/takeover_candidates.csv"
                        takeover_count=$((takeover_count + 1))
                        ;;
                    *)
                        echo "$subdomain,$cname,$svc,UNLIKELY-$code" >> "$OUTDIR/cloud/takeover_candidates.csv"
                        ;;
                esac
                break
            fi
        done
    done < "$OUTDIR/subdomains_live.txt" 2>/dev/null || true

    info "Buckets S3/Azure → ${BUCKETS_FOUND}"
    [ "$takeover_count" -gt 0 ] && \
        warn "Candidatos a subdomain takeover → ${takeover_count}" || \
        info "Subdomain takeover → nenhum candidato"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 9 — BUILD OUTPUT FILES (integração SWARM)
# ═══════════════════════════════════════════════════════════════════════════════
phase_build_outputs() {
    phase "FASE 9 — BUILD OUTPUT FILES"
    [ "$ABORT" = true ] && return 130

    # targets_enriched.txt — entrada para swarm.sh
    step "Gerando targets_enriched.txt"
    {
        if [ -f "$OUTDIR/subdomains_live.txt" ]; then
            awk '{print $1}' "$OUTDIR/subdomains_live.txt" | while IFS= read -r h; do
                [ -n "$h" ] && echo "https://$h"
            done
        elif [ -f "$OUTDIR/subdomains_passive.txt" ]; then
            while IFS= read -r h; do
                [ -n "$h" ] && echo "https://$h"
            done < "$OUTDIR/subdomains_passive.txt"
        fi
        # IPs diretos
        while IFS= read -r ip; do
            [ -n "$ip" ] && echo "https://$ip"
        done < "$OUTDIR/main_ips.txt" 2>/dev/null || true
    } | sort -u > "$OUTDIR/targets_enriched.txt" 2>/dev/null || true

    local target_count
    target_count=$(wc -l < "$OUTDIR/targets_enriched.txt" 2>/dev/null || echo 0)
    info "targets_enriched.txt → ${target_count} alvos"

    # endpoints_historical.txt — para ffuf/nuclei no swarm.sh
    [ -f "$OUTDIR/interesting_endpoints.txt" ] && \
        cp "$OUTDIR/interesting_endpoints.txt" "$OUTDIR/endpoints_historical.txt" 2>/dev/null || true

    # osint_summary.json — metadados legíveis por máquina
    python3 -c "
import json
summary = {
    'target':          '$DOMAIN',
    'base_domain':     '$BASE_DOMAIN',
    'org_name':        '$ORG_NAME',
    'timestamp':       '$(ts)',
    'osint_version':   '$VERSION',
    'output_dir':      '$OUTDIR',
    'stats': {
        'subdomains_found':  $SUBDOMAINS_FOUND,
        'emails_found':      $EMAILS_FOUND,
        'historical_urls':   $URLS_FOUND,
        'leaks_found':       $LEAKS_FOUND,
        'buckets_found':     $BUCKETS_FOUND,
    },
    'files': {
        'targets_enriched':     'targets_enriched.txt',
        'leaked_creds':         'leaked_creds.csv',
        'subdomains_passive':   'subdomains_passive.txt',
        'subdomains_live':      'subdomains_live.txt',
        'emails':               'emails.txt',
        'historical_urls':      'historical_urls.txt',
        'interesting_endpoints':'interesting_endpoints.txt',
        'report':               'osint_report.html',
    }
}
print(json.dumps(summary, indent=2))
" 2>/dev/null > "$OUTDIR/osint_summary.json" || true
    info "osint_summary.json gerado"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FASE 10 — RELATÓRIO HTML
# ═══════════════════════════════════════════════════════════════════════════════
phase_report() {
    phase "FASE 10 — GERAÇÃO DE RELATÓRIO HTML"
    [ "$ABORT" = true ] && return 130

    step "Gerando osint_report.html"

    # Exportar variáveis para o heredoc Python
    local _outdir="$OUTDIR"
    local _domain="$DOMAIN"
    local _version="$VERSION"
    local _subdomains="$SUBDOMAINS_FOUND"
    local _emails="$EMAILS_FOUND"
    local _urls="$URLS_FOUND"
    local _leaks="$LEAKS_FOUND"
    local _buckets="$BUCKETS_FOUND"

    python3 - "$_outdir" "$_domain" "$_version" \
              "$_subdomains" "$_emails" "$_urls" "$_leaks" "$_buckets" << 'PYEOF'
import sys, os, html, datetime

outdir, domain, version  = sys.argv[1], sys.argv[2], sys.argv[3]
subdomains, emails, urls = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
leaks, buckets           = int(sys.argv[7]), int(sys.argv[8])
ts_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def read_lines(name, limit=500):
    path = os.path.join(outdir, name)
    if not os.path.exists(path):
        return []
    with open(path, errors='replace') as f:
        return f.readlines()[:limit]

def table_section(title, filename, limit=300):
    lines = read_lines(filename, limit)
    rows = ""
    odd = False
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cls = "ro" if odd else "re"
        odd = not odd
        rows += f'<tr class="{cls}"><td>{html.escape(line)}</td></tr>'
    if not rows:
        rows = '<tr><td class="empty">Nenhum dado coletado</td></tr>'
    return f"""
<div class="sec">
  <h2>{html.escape(title)}</h2>
  <table><tbody>{rows}</tbody></table>
</div>"""

alert_leak   = ' alert' if leaks   > 0 else ''
alert_bucket = ' alert' if buckets > 0 else ''

report = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>SWARM OSINT — {html.escape(domain)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;font-size:13px}}
.hdr{{background:linear-gradient(135deg,#1a1f2e,#0d1117);border-bottom:2px solid #f0a500;padding:28px 40px}}
.hdr h1{{color:#f0a500;font-size:22px;letter-spacing:2px}}
.hdr .meta{{color:#8b949e;margin-top:8px;font-size:12px}}
.wrap{{max-width:1400px;margin:0 auto;padding:28px 40px}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:28px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;text-align:center}}
.card .val{{font-size:30px;font-weight:bold;color:#f0a500}}
.card .lbl{{font-size:11px;color:#8b949e;margin-top:5px;text-transform:uppercase;letter-spacing:1px}}
.card.alert{{border-color:#da3633}}.card.alert .val{{color:#f85149}}
.sec{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:20px;overflow:hidden}}
.sec h2{{background:#1c2128;border-bottom:1px solid #30363d;padding:12px 20px;font-size:13px;color:#e6edf3;letter-spacing:1px}}
table{{width:100%;border-collapse:collapse}}
td{{padding:6px 20px;font-size:11px;font-family:Consolas,monospace;word-break:break-all}}
.re{{background:#161b22}}.ro{{background:#1c2128}}
td.empty{{color:#8b949e;font-style:italic;text-align:center;padding:18px}}
.ftr{{text-align:center;color:#30363d;font-size:11px;padding:20px;margin-top:16px}}
</style>
</head>
<body>
<div class="hdr">
  <h1>⚑ SWARM OSINT — Pre-Engagement Intelligence Report</h1>
  <div class="meta">Alvo: <strong>{html.escape(domain)}</strong> &nbsp;|&nbsp; Gerado: {ts_now} &nbsp;|&nbsp; SWARM OSINT v{html.escape(version)}</div>
</div>
<div class="wrap">
  <div class="grid">
    <div class="card"><div class="val">{subdomains}</div><div class="lbl">Subdomínios</div></div>
    <div class="card"><div class="val">{emails}</div><div class="lbl">E-mails</div></div>
    <div class="card"><div class="val">{urls}</div><div class="lbl">URLs Históricas</div></div>
    <div class="card{alert_leak}"><div class="val">{leaks}</div><div class="lbl">Vazamentos</div></div>
    <div class="card{alert_bucket}"><div class="val">{buckets}</div><div class="lbl">Cloud Buckets</div></div>
  </div>
  {table_section("DNS Records", "dns_records.txt", 100)}
  {table_section("Subdomínios Passivos", "subdomains_passive.txt", 500)}
  {table_section("Subdomínios Ativos (dnsx)", "subdomains_live.txt", 500)}
  {table_section("E-mails Coletados", "emails.txt", 200)}
  {table_section("Endpoints Históricos (com parâmetros)", "interesting_endpoints.txt", 300)}
  {table_section("Cloud — Buckets Identificados", "cloud/buckets_found.csv", 100)}
  {table_section("Cloud — Candidatos Subdomain Takeover", "cloud/takeover_candidates.csv", 100)}
  {table_section("Shodan — Serviços Expostos", "shodan/exposed_services.txt", 100)}
  {table_section("Shodan — CVEs Identificados", "shodan/cves_from_shodan.txt", 100)}
  {table_section("Email Security (SPF/DMARC/DKIM)", "email_security.txt", 50)}
</div>
<div class="ftr">SWARM OSINT v{html.escape(version)} — USO EXCLUSIVO EM AMBIENTES AUTORIZADOS</div>
</body>
</html>"""

out_path = os.path.join(outdir, "osint_report.html")
with open(out_path, "w") as f:
    f.write(report)
print(out_path)
PYEOF

    if [ -f "$OUTDIR/osint_report.html" ]; then
        info "Relatório → $OUTDIR/osint_report.html"
    else
        warn "Falha ao gerar relatório HTML"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  RESUMO FINAL
# ═══════════════════════════════════════════════════════════════════════════════
summary() {
    echo ""
    echo -e "${CYN}════════════════════════════════════════════════════════════════${RST}"
    echo -e "  ${BLD}${CYN}SWARM OSINT — CONCLUÍDO${RST}"
    echo -e "${CYN}════════════════════════════════════════════════════════════════${RST}"
    echo ""
    echo -e "  ${BLD}Alvo:${RST}      $DOMAIN"
    echo -e "  ${BLD}Duração:${RST}   $(elapsed)"
    echo -e "  ${BLD}Output:${RST}    $OUTDIR/"
    echo ""
    echo -e "  ${CYN}─── Resultados ────────────────────────────────────────────${RST}"
    echo -e "  ${GRN}[✓]${RST} Subdomínios:       ${BLD}${SUBDOMAINS_FOUND}${RST}"
    echo -e "  ${GRN}[✓]${RST} E-mails:           ${BLD}${EMAILS_FOUND}${RST}"
    echo -e "  ${GRN}[✓]${RST} URLs históricas:   ${BLD}${URLS_FOUND}${RST}"
    if [ "$LEAKS_FOUND" -gt 0 ]; then
        echo -e "  ${RED}[!]${RST} Vazamentos:        ${BLD}${RED}${LEAKS_FOUND}${RST}"
    else
        echo -e "  ${GRN}[✓]${RST} Vazamentos:        0"
    fi
    if [ "$BUCKETS_FOUND" -gt 0 ]; then
        echo -e "  ${YLW}[!]${RST} Cloud buckets:     ${BLD}${YLW}${BUCKETS_FOUND}${RST}"
    else
        echo -e "  ${GRN}[✓]${RST} Cloud buckets:     0"
    fi
    echo ""
    echo -e "  ${CYN}─── Arquivos-chave ────────────────────────────────────────${RST}"
    echo -e "  ${BLD}targets_enriched.txt${RST}     → entrada para swarm.sh"
    echo -e "  ${BLD}leaked_creds.csv${RST}         → entrada para swarm_red.sh (hydra)"
    echo -e "  ${BLD}osint_report.html${RST}        → relatório completo"
    echo -e "  ${BLD}osint_summary.json${RST}       → metadados legíveis por máquina"
    echo ""
    echo -e "  ${CYN}─── Próximo passo ─────────────────────────────────────────${RST}"
    echo -e "  ${DIM}bash swarm.sh ${DOMAIN} --osint-dir ${OUTDIR}/${RST}"
    echo ""
    echo -e "${CYN}════════════════════════════════════════════════════════════════${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    banner
    parse_args "$@"
    validate_tools
    confirm_roe
    setup_output

    phase_domain_intel
    phase_subdomain_discovery
    phase_email_harvesting
    phase_historical_urls
    phase_github_dorking
    phase_leaked_creds
    phase_shodan
    phase_cloud_surface
    phase_build_outputs
    phase_report

    summary
}

main "$@"
