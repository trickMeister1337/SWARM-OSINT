# Guia de Tuning e Atualização - SWARM

## 1. Comandos de Atualização
Para garantir que suas ferramentas estejam sempre na última versão:

```bash
# Atualizar Nuclei e Templates
nuclei -update && nuclei -update-templates

# Atualizar httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Atualizar Katana (Spider)
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## 2. Tuning para Performance
Se você estiver em um ambiente com alta largura de banda, pode aumentar a velocidade:

*   **Nuclei:** Use `-rate-limit 150 -concurrency 50` para scans agressivos.
*   **Httpx:** Use `-threads 100` para descoberta rápida.

## 3. Tuning para Evasão (Stealth)
Se o alvo possui WAF:

*   **Nuclei:** Use `-delay 1s` para evitar bloqueios por IP.
*   **Headers:** O script já rotaciona User-Agents, mas você pode adicionar `-H "X-Forwarded-For: 127.0.0.1"` para tentar bypass simples.

## 4. Higienização do Código
O novo SWARM agora é modular:
*   `swarm.sh`: Orquestrador principal.
*   `lib/`: Contém a inteligência em Python (fácil de debugar).
*   `raw/`: Armazena dados brutos para auditoria.
