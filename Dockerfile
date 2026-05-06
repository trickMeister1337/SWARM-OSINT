FROM kalilinux/kali-rolling:latest

LABEL maintainer="trickMeister1337"
LABEL description="SWARM — Security Web Assessment & Recon Module"
LABEL version="2026"

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin:/usr/local/go/bin:/usr/local/bin

# ── Pacotes do sistema ────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl python3 python3-pip jq nmap git \
    zaproxy testssl.sh chromium \
    golang-go dnsutils wget ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Python ────────────────────────────────────────────────────────
RUN pip3 install --break-system-packages \
    requests pdfminer.six wafw00f

# ── Ferramentas Go ────────────────────────────────────────────────
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    nuclei -update-templates -silent

# ── trufflehog ───────────────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# ── smuggler ─────────────────────────────────────────────────────
RUN git clone https://github.com/defparam/smuggler /root/tools/smuggler

# ── SWARM ────────────────────────────────────────────────────────
WORKDIR /swarm
COPY swarm.sh swarm_batch.sh swarm_diff.py vuln_patterns.json ./
COPY lib/ ./lib/
RUN chmod +x swarm.sh swarm_batch.sh

# Volume para output de scans
VOLUME ["/swarm/output"]

# ── Entrypoint ────────────────────────────────────────────────────
# Uso: docker run --rm -v $(pwd)/output:/swarm/output trickmeister1337/swarm https://target.com
# Scan autenticado: docker run --rm ... trickmeister1337/swarm https://target.com --token "eyJ..."
ENTRYPOINT ["bash", "swarm.sh"]
