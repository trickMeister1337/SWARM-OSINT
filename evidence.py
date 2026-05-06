#!/usr/bin/env python3
"""SWARM RED — Extração de evidências e consolidação de findings."""
import sys, os, json, re, glob, csv
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse

def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]|\033\[[0-9;]*[a-zA-Z]', '', text)

def is_valid_url(url):
    if not url or not isinstance(url, str): return False
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"): return False
    try:
        p = urlparse(url)
        if not p.hostname or len(p.hostname) < 3: return False
        if "." not in p.hostname: return False
        if p.hostname.endswith("_output.log"): return False
        return True
    except: return False

NOT_TABLE_WORDS = frozenset({"ending","starting","shutting","testing","resuming","flushing","cleaning","fetched","heuristic","loading","connection","back-end","parameter","retrieved","legal","usage"})

def extract_sqlmap_evidence(log_content, log_dir):
    log_content = strip_ansi(log_content)
    info = {"target_url":"","parameter":"","place":"","techniques":[],"dbms":"","current_user":"","current_db":"","banner":"","tables":[],"csv_data":[],"injectable":False}
    for line in log_content.split("\n"):
        l = line.strip(); ll = l.lower()
        clean = re.sub(r"\[\d{2}:\d{2}:\d{2}\]\s*\[\w+\]\s*", "", l)
        if "parameter '" in ll and ("is vulnerable" in ll or "injectable" in ll):
            info["injectable"] = True
            m = re.search(r"parameter '([^']+)'", l)
            if m: info["parameter"] = m.group(1)
        if "sqlmap identified the following injection" in ll: info["injectable"] = True
        if "place:" in ll and not info["place"]:
            m = re.search(r"Place:\s*(\w+)", l, re.I)
            if m: info["place"] = m.group(1)
        if "type:" in ll and any(t in ll for t in ["boolean","time","union","error","stacked","inline"]):
            tech = re.sub(r"^.*Type:\s*", "", clean, flags=re.I).strip()
            if tech and tech not in info["techniques"] and "testing" not in ll: info["techniques"].append(tech)
        if "back-end dbms:" in ll: info["dbms"] = clean.split(":",1)[-1].strip()
        if "current user:" in ll and ":" in l and "testing" not in ll: info["current_user"] = clean.split(":",1)[-1].strip().strip("'\"")
        if "current database:" in ll and ":" in l and "testing" not in ll: info["current_db"] = clean.split(":",1)[-1].strip().strip("'\"")
        if "banner:" in ll and "testing" not in ll: info["banner"] = clean.split(":",1)[-1].strip().strip("'\"")
        if re.match(r"^\[\*\]\s+\w", l):
            val = re.sub(r"^\[\*\]\s+", "", l).strip()
            fw = val.split()[0].lower() if val.split() else ""
            if val and len(val)<60 and fw not in NOT_TABLE_WORDS and not re.match(r"\d{2}:\d{2}:\d{2}", val) and val not in info["tables"]: info["tables"].append(val)
        m = re.search(r"testing URL '([^']+)'", l)
        if m and is_valid_url(m.group(1)): info["target_url"] = m.group(1)
        m = re.search(r"target URL:\s*(\S+)", l, re.I)
        if m and is_valid_url(m.group(1)): info["target_url"] = m.group(1)
    csv_paths = []
    for pat in [f"{log_dir}/results-*.csv", f"{log_dir}/*/results-*.csv"]: csv_paths.extend(glob.glob(pat))
    for d in glob.glob(f"{log_dir}/*/"): csv_paths.extend(glob.glob(f"{d}results-*.csv"))
    csv_paths = list(set(csv_paths))
    for cp in csv_paths[:3]:
        try:
            with open(cp) as f:
                rows = list(csv.reader(f))
                if len(rows) > 1: info["csv_data"].append({"file": os.path.basename(cp), "header": rows[0], "rows": rows[1:10]})
        except: pass
    for dp in glob.glob(f"{log_dir}/dump/**/*.csv", recursive=True)[:3]:
        try:
            with open(dp) as f:
                rows = list(csv.reader(f))
                if rows: info["csv_data"].append({"file": f"dump/{os.path.basename(dp).replace('.csv','')}", "header": rows[0], "rows": rows[1:10]})
        except: pass
    return info

def format_evidence(info):
    parts = []
    if info["parameter"]:
        line = f"Parâmetro vulnerável: {info['parameter']}"
        if info["place"]: line += f" ({info['place']})"
        parts.append(line)
    if info["techniques"]:
        parts.append("Técnica(s) de injeção:")
        for t in info["techniques"][:5]: parts.append(f"  • {t}")
    if info["dbms"]: parts.append(f"DBMS: {info['dbms']}")
    if info["banner"]: parts.append(f"Banner: {info['banner']}")
    if info["current_user"]: parts.append(f"Usuário DB: {info['current_user']}")
    if info["current_db"]: parts.append(f"Database: {info['current_db']}")
    if info["tables"]:
        parts.append("Databases/Tabelas:")
        for t in info["tables"][:10]: parts.append(f"  • {t}")
    if info["csv_data"]:
        for ci in info["csv_data"][:2]:
            parts.append(f"\nDados extraídos ({ci['file']}):")
            if ci["header"]: parts.append("  " + " | ".join(str(h) for h in ci["header"])); parts.append("  " + "-" * min(70, len(" | ".join(str(h) for h in ci["header"]))))
            for row in ci["rows"][:5]: parts.append("  " + " | ".join(str(c) for c in row))
            if len(ci["rows"]) > 5: parts.append(f"  ... ({len(ci['rows'])} registros)")
    if not parts: return None
    if not info["parameter"] and not info["techniques"] and not info["dbms"]:
        if not info["csv_data"] or all(len(c["rows"])==0 for c in info["csv_data"]): return None
    return "\n".join(parts[:25])

def collect_and_consolidate(outdir):
    def _rf(p, lim=None):
        try:
            with open(p) as f: c = f.read(); return strip_ansi(c[-lim:] if lim else c)
        except: return ""
    def _rl(p):
        try:
            with open(p) as f: return [l.strip() for l in f if l.strip()]
        except: return []
    def _rj(p):
        try:
            with open(p) as f: return json.load(f)
        except: return []
    sqli_results = []
    for f in sorted(glob.glob(f"{outdir}/sqlmap/*_output.log")):
        with open(f) as fh: c = fh.read()
        c_clean = strip_ansi(c)
        vuln = bool(re.search(r"parameter .* is vulnerable|is injectable|sqlmap identified the following injection", c_clean, re.I))
        info = extract_sqlmap_evidence(c, os.path.dirname(f))
        info["injectable"] = info["injectable"] or vuln
        evidence = format_evidence(info)
        target_url = info["target_url"]
        if not target_url or not is_valid_url(target_url):
            m = re.search(r"testing URL '([^']+)'", c_clean)
            if m and is_valid_url(m.group(1)): target_url = m.group(1)
            else:
                m = re.search(r"-u ['\"]?([^\s'\"]+)", c_clean)
                target_url = m.group(1) if m and is_valid_url(m.group(1)) else ""
        if target_url and is_valid_url(target_url):
            sqli_results.append({"file": os.path.basename(f), "vulnerable": info["injectable"], "evidence": evidence, "target_url": target_url, "info": info})
    msf_log = _rf(f"{outdir}/metasploit/msf_output.log", 4000)
    hydra_results = []
    for f in glob.glob(f"{outdir}/hydra/*_results.txt"):
        c = _rf(f).strip()
        if c: hydra_results.append({"service": os.path.basename(f).replace("_results.txt",""), "content": c})
    nikto_findings = []
    nd = _rj(f"{outdir}/nikto/nikto_report.json")
    if isinstance(nd, dict): nikto_findings = nd.get("vulnerabilities", [])
    elif isinstance(nd, list): nikto_findings = [x for x in nd if isinstance(x, dict)]
    confirmed = []
    for line in _rl(f"{outdir}/exploits_confirmed.csv"):
        p = line.split("|")
        if len(p) >= 3 and p[0] != "status" and is_valid_url(p[1]):
            confirmed.append({"status": p[0], "target": p[1], "tool": p[2], "detail": p[3] if len(p)>3 else ""})
    cves = _rl(f"{outdir}/cves_found.txt")
    services = _rl(f"{outdir}/open_services.txt")
    log_content = _rf(f"{outdir}/swarm_red.log", 3000)
    zap_hc = []
    for line in _rl(f"{outdir}/zap_high_crit.txt"):
        p = line.split("|")
        if len(p) >= 3: zap_hc.append({"risk": p[0], "alert": p[1], "url": p[2]})
    ssd = {}
    for f in glob.glob(f"{outdir}/searchsploit/CVE-*.json"):
        cv = os.path.basename(f).replace(".json","")
        d = _rj(f)
        if isinstance(d, dict):
            ex = d.get("RESULTS_EXPLOIT", [])
            if ex: ssd[cv] = ex
    kev_matches = {}; kd = _rj(f"{outdir}/input_kev_matches.json")
    if isinstance(kd, dict): kev_matches = kd
    cve_enrichment = {}; cd = _rj(f"{outdir}/input_cve_enrichment.json")
    if isinstance(cd, dict): cve_enrichment = cd
    findings = []; vc = [c for c in confirmed if c["status"]=="VULNERABLE"]
    cg = {}
    for c in vc:
        base = re.sub(r"\?.*$","",c["target"]).rstrip("/")
        path = re.sub(r"https?://[^/]+","",base)
        key = (c["tool"], path)
        if key not in cg: cg[key] = {"urls": [], "tool": c["tool"], "detail": c.get("detail","")}
        if c["target"] not in cg[key]["urls"]: cg[key]["urls"].append(c["target"])
    for key, grp in cg.items():
        urls = grp["urls"]; tool = grp["tool"]; n = len(urls)
        best_ev = None
        for sr in sqli_results:
            if sr["vulnerable"] and sr["evidence"]:
                sr_base = re.sub(r"\?.*$","",sr["target_url"]).rstrip("/")
                for u in urls:
                    if re.sub(r"\?.*$","",u).rstrip("/") == sr_base: best_ev = sr["evidence"]; break
                if best_ev: break
        if not best_ev:
            for sr in sqli_results:
                if sr["vulnerable"] and sr["evidence"]: best_ev = sr["evidence"]; break
        if not best_ev: continue
        ev_parts = [best_ev, f"\nEndpoints afetados ({n}):"]
        for u in urls[:20]: ev_parts.append(f"  • {u}")
        if n > 20: ev_parts.append(f"  ... e mais {n-20}")
        hn = ""
        try: hn = urlparse(urls[0]).hostname or ""
        except: pass
        findings.append({"sev":"High","title":f"SQL Injection — {tool} ({n} endpoints)" if n>1 else f"SQL Injection — {tool}","target":urls[0] if n==1 else f"{n} endpoints em {hn}","tool":tool,"detail":"\n".join(ev_parts),"type":"sqli","count":n,"endpoints":urls})
    cu = set(u for g in cg.values() for u in g["urls"])
    um = [r for r in sqli_results if r["vulnerable"] and r["evidence"] and r["target_url"] not in cu]
    if um:
        groups = {}
        for r in um:
            ek = (r["info"]["parameter"], r["info"]["dbms"])
            if ek not in groups: groups[ek] = {"items": [], "evidence": r["evidence"]}
            groups[ek]["items"].append(r)
        for ek, grp in groups.items():
            items = grp["items"]; n = len(items); urls = list(set(r["target_url"] for r in items))
            ep = [grp["evidence"]] if grp["evidence"] else []
            if n > 1:
                ep.append(f"\nEndpoints ({n}):")
                for u in urls[:15]: ep.append(f"  • {u}")
            findings.append({"sev":"High","title":f"SQL Injection Confirmada ({n} endpoints)" if n>1 else "SQL Injection Confirmada","target":urls[0] if n==1 else f"{n} endpoints","tool":"sqlmap","detail":"\n".join(ep) or "Injeção SQL confirmada","type":"sqli","count":n,"endpoints":urls})
    for r in hydra_results:
        findings.append({"sev":"High","title":f"Credenciais Fracas — {r['service'].upper()}","target":r["service"],"tool":"hydra","detail":r["content"][:400],"type":"bruteforce","count":1,"endpoints":[]})
    seen = set(); deduped = []
    for f in findings:
        key = (f["tool"], f["type"], f.get("count",0))
        if key not in seen: seen.add(key); deduped.append(f)
    return {"findings":deduped,"sqli_results":sqli_results,"msf_log":msf_log,"hydra_results":hydra_results,"nikto_findings":nikto_findings,"confirmed":confirmed,"cves":cves,"services":services,"log_content":log_content,"zap_hc":zap_hc,"searchsploit":ssd,"kev_matches":kev_matches,"cve_enrichment":cve_enrichment}

if __name__ == "__main__":
    if len(sys.argv) < 2: print(__doc__); sys.exit(1)
    r = collect_and_consolidate(sys.argv[1])
    print(json.dumps({"findings":len(r["findings"]),"sqli_vuln":len([x for x in r["sqli_results"] if x["vulnerable"]]),"cves":len(r["cves"]),"services":len(r["services"])}, indent=2))
