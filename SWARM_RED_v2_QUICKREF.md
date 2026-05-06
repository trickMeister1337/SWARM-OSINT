# SWARM RED v2 — QUICK REFERENCE CARD

```
  ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗    ██████╗ ███████╗██████╗ 
  ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║    ██╔══██╗██╔════╝██╔══██╗
  ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║    ██████╔╝█████╗  ██║  ██║
  ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║    ██╔══██╗██╔══╝  ██║  ██║
  ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║    ██║  ██║███████╗██████╔╝
  ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚══════╝╚═════╝ 
                    Automated Exploitation Engine v2.0
```

---

## 🚀 COMANDOS RÁPIDOS

### Uso Básico

```bash
# Standalone (mais comum)
bash swarm_red.sh -t <target> --standalone -p <profile>

# Com resultados do SWARM
bash swarm_red.sh -d ~/swarm_results/scan_<domain>_<timestamp>/

# Dry run (simulação)
bash swarm_red.sh -t <target> --standalone --dry-run
```

---

## 📋 PERFIS

| Perfil | SQLMap | Brute Force | Nikto | Uso |
|--------|--------|-------------|-------|-----|
| **staging** | L3 R2 T5 | ✅ Sim | ✅ Sim | Homolog/QA |
| **lab** | L5 R3 T10 | ✅ Sim | ✅ Sim | Lab descartável |
| **production** | L1 R1 T1 | ❌ Não | ❌ Não | Prod (janela aprovada) |

---

## 📊 OUTPUT DO SCAN

```
swarm_red_<target>_<timestamp>/
├── relatorio_swarm_red.html    ← Relatório principal
├── exploits_confirmed.csv      ← Exploits com dump real
├── false_positives.csv         ← Detectados sem confirmação
├── evidence/
│   ├── evidence_001.txt        ← Evidência estruturada
│   └── evidence_002.txt
├── sqlmap/
│   └── <hash>/log              ← Logs SQLMap
├── metasploit/
│   └── swarm_red.rc            ← Resource script MSF
└── swarm_red.log               ← Log completo
```

---

## ✅ CRITÉRIOS DE CONFIRMAÇÃO

Um exploit é marcado como **CONFIRMADO** somente se:

1. ✓ **Databases enumeradas** (ex: production_db, admin_db)
2. ✓ **Tabelas enumeradas** (ex: users, payments, sessions)
3. ✓ **Registros dumpados** (dump_count > 0)
4. ✓ **Payload capturado** (SQL injection que funcionou)

**Caso contrário** → `false_positives.csv`

---

## 🎯 EXEMPLOS PRÁTICOS

### Scan em Staging

```bash
bash swarm_red.sh -t webapp-staging.omnibees.com --standalone -p staging

# Resultado esperado:
# - 2-5 exploits confirmados
# - 10-20 false positives (WAF)
# - RCE tentado automaticamente
# - Duração: 30-60 min
```

### Scan em Lab (máxima agressividade)

```bash
bash swarm_red.sh -t 192.168.100.50 --standalone -p lab

# Resultado esperado:
# - 5-15 exploits confirmados
# - Brute force completo
# - Duração: 2-4 horas
```

### Scan em Produção (minimal impact)

```bash
bash swarm_red.sh -t api.omnibees.com --standalone -p production

# Resultado esperado:
# - Apenas confirmação (SEM dump)
# - Max 10 exploits testados
# - Duração: 30-60 min
```

---

## 📈 INTERPRETANDO RESULTADOS

### Sumário Executivo

```
Testes executados:      27
✓ Exploits confirmados: 2   ← COM DUMP (evidência real)
⚠ Detectados sem dump:  24  ← WAF/proteção bloqueou
✗ Falsos positivos:     1   ← Resultado inconclusivo
Taxa de confirmação:    7%  ← 2/27
```

### Evidência VÁLIDA

```
Tipo de Banco: MySQL 5.7.38
Total de Registros Dumpados: 127

• https://webapp.bee2pay.com?user=1
  Databases: production_db,staging_db
  Tabelas: users,payments,sessions
  Registros: 127
  Payload: 1' UNION SELECT NULL,table_name...
```

### Evidência INVÁLIDA (v1)

```
Bases/Tabelas encontradas:
  • ending @ 19:13:50 /2026-04-29/
  
❌ SEM databases, tabelas ou dados
```

---

## 🔧 TROUBLESHOOTING RÁPIDO

| Problema | Solução |
|----------|---------|
| "lib/ não encontrado" | Script extrai automaticamente, aguarde |
| Todos marcados "UNCONFIRMED" | Aumentar timeout ou usar perfil `lab` |
| CSV com colunas faltando | Verificar versão: `grep VERSION swarm_red.sh` |
| False positives altos | Normal se WAF ativo; ver seção 8c do relatório |

---

## 🔐 PÓS-SCAN (IMPORTANTE)

```bash
# 1. Criptografar resultados
tar czf results.tar.gz swarm_red_*/
gpg -c results.tar.gz

# 2. Deletar dumps não criptografados
shred -vfz results.tar.gz
rm -rf swarm_red_*/

# 3. Compartilhar APENAS results.tar.gz.gpg
```

---

## 📞 SUPORTE

**Versão**: 2.0.0  
**Autor**: Trick (Security Engineering)  
**Status**: ✅ Production Ready

---

**FIM DO QUICK REFERENCE**
