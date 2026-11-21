#!/usr/bin/env python3
"""Cold email deliverability audit for one sending domain. Usage: audit.py domain [--json]"""
import subprocess, sys, json, re, datetime, urllib.request

def dig(name, rtype="TXT"):
    try:
        out = subprocess.run(["dig", "+short", "+time=3", "+tries=2", rtype, name], capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return []
    lines = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(";")]
    if rtype == "TXT":
        lines = ["".join(re.findall(r'"([^"]*)"', l)) or l for l in lines]
    return lines

def spf_lookups(record, depth=0, seen=None):
    seen = seen or set(); n = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith(("include:", "redirect=")):
            n += 1; dom = t.split(":", 1)[-1].split("=", 1)[-1]
            if dom in seen or depth > 10: continue
            seen.add(dom)
            sub = [r for r in dig(dom) if r.lower().startswith("v=spf1")]
            if sub: n += spf_lookups(sub[0], depth + 1, seen)
        elif t.startswith(("a", "mx", "ptr", "exists:")) and not t.startswith("all"):
            n += 1
    return n

SELECTORS = ["google", "selector1", "selector2", "zoho", "zmail", "k1", "k2", "s1", "s2", "default", "mail", "dkim", "smtp", "mxvault", "sig1", "everlytickey1", "mandrill", "pm", "zendesk1", "protonmail", "fm1", "hs1", "hs2", "sendgrid"]
DOMAIN_BL = {"Spamhaus DBL": "dbl.spamhaus.org", "SURBL": "multi.surbl.org", "URIBL": "multi.uribl.com"}
IP_BL = {"Spamhaus ZEN": "zen.spamhaus.org", "Barracuda": "b.barracudacentral.org", "SpamCop": "bl.spamcop.net"}

def listed(q):
    a = dig(q, "A")
    if not a: return False, None
    if any(x.startswith("127.255.255.") or x == "127.0.0.1" and "uribl" in q for x in a):
        return None, a  # resolver blocked / query refused
    return True, a

def audit(domain):
    r = {"domain": domain, "date": datetime.date.today().isoformat(), "checks": [], "fixes": []}
    def add(area, status, detail, fix=None, sev=None):
        r["checks"].append({"area": area, "status": status, "detail": detail})
        if fix: r["fixes"].append({"severity": sev or "medium", "area": area, "fix": fix})
    mx = dig(domain, "MX")
    if mx:
        hosts = [m.split()[-1].rstrip(".") for m in mx]
        prov = "Google Workspace" if any("google" in h for h in hosts) else "Microsoft 365" if any("outlook" in h for h in hosts) else "Zoho" if any("zoho" in h for h in hosts) else "Other"
        add("MX", "pass", f"{len(hosts)} MX record(s), provider looks like {prov}: {', '.join(hosts)}")
    else:
        hosts = []; add("MX", "fail", "No MX records: replies to this domain bounce.", "Add MX records for your mailbox provider so replies are received.", "high")
    spf = [t for t in dig(domain) if t.lower().startswith("v=spf1")]
    if not spf:
        add("SPF", "fail", "No SPF record.", "Publish one SPF record listing every service that sends as this domain, ending in ~all or -all.", "high")
    elif len(spf) > 1:
        add("SPF", "fail", f"{len(spf)} SPF records found; receivers treat this as a permanent error.", "Merge into a single SPF record.", "high")
    else:
        s = spf[0]; n = spf_lookups(s); tail = s.split()[-1]
        st = "pass" if n <= 10 and tail in ("~all", "-all") else "warn"
        add("SPF", st, f"{s}  ({n} DNS lookups, limit 10; ends with {tail})",
            None if st == "pass" else ("Reduce SPF includes below 10 lookups." if n > 10 else "End SPF with ~all or -all, never +all or ?all."), "high" if n > 10 else "medium")
    found = []
    for sel in SELECTORS:
        t = dig(f"{sel}._domainkey.{domain}")
        if any("p=" in x for x in t): found.append(sel)
    if found: add("DKIM", "pass", "DKIM key published for selector(s): " + ", ".join(found))
    else: add("DKIM", "warn", "No DKIM key found on common selectors (a custom selector may exist).", "Confirm DKIM signing is enabled at the mail provider and publish its key; send a test to check headers show dkim=pass.", "high")
    dm = [t for t in dig(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not dm:
        add("DMARC", "fail", "No DMARC record.", "Publish DMARC, starting at p=none with a rua report address, then move to quarantine.", "high")
    else:
        d = dm[0]; p = re.search(r"\bp=(\w+)", d); rua = "rua=" in d
        pol = p.group(1) if p else "missing"
        st = "pass" if pol in ("quarantine", "reject") and rua else "warn"
        fix = None
        if pol == "none": fix = "Move DMARC from p=none to p=quarantine once reports show all legitimate mail passing."
        if not rua: fix = (fix + " " if fix else "") + "Add a rua= address so you receive aggregate reports."
        add("DMARC", st, d, fix, "medium")
    sts = dig(f"_mta-sts.{domain}"); tls = dig(f"_smtp._tls.{domain}")
    add("MTA-STS / TLS-RPT", "info", f"MTA-STS {'present' if sts else 'absent'}, TLS-RPT {'present' if tls else 'absent'} (optional, improves trust on large receivers).")
    bimi = dig(f"default._bimi.{domain}")
    add("BIMI", "info", "BIMI record present." if bimi else "No BIMI (optional; needs DMARC at quarantine or reject).")
    hits, unk = [], []
    for name, zone in DOMAIN_BL.items():
        ok, a = listed(f"{domain}.{zone}")
        (hits if ok else unk if ok is None else []).append(name)
    ips = []
    for h in hosts[:2]:
        ips += dig(h, "A")[:2]
    for ip in ips[:4]:
        rev = ".".join(reversed(ip.split(".")))
        for name, zone in IP_BL.items():
            ok, a = listed(f"{rev}.{zone}")
            (hits if ok else unk if ok is None else []).append(f"{name} ({ip})")
    if hits: add("Blocklists", "fail", "Listed on: " + ", ".join(hits), "Find and stop the cause, then request delisting from each list.", "high")
    else: add("Blocklists", "pass", f"Domain clean on {', '.join(DOMAIN_BL)}; MX IPs clean on {', '.join(IP_BL)}." + (f" Could not query: {', '.join(sorted(set(unk)))}." if unk else ""))
    try:
        with urllib.request.urlopen(f"https://rdap.org/domain/{domain}", timeout=15) as f:
            ev = json.load(f).get("events", [])
        reg = next((e["eventDate"][:10] for e in ev if e.get("eventAction") == "registration"), None)
        if reg:
            age = (datetime.date.today() - datetime.date.fromisoformat(reg)).days
            add("Domain age", "pass" if age >= 30 else "warn", f"Registered {reg} ({age} days old).", None if age >= 30 else "Domains under 30 days old should only send warmup volume.", "medium")
    except Exception:
        add("Domain age", "info", "Registration date not available.")
    try:
        req = urllib.request.Request(f"https://{domain}", headers={"User-Agent": "Mozilla/5.0"})
        code = urllib.request.urlopen(req, timeout=15).status
        add("Website", "pass" if code == 200 else "warn", f"https://{domain} returns {code}.")
    except Exception as e:
        add("Website", "warn", f"https://{domain} did not load ({type(e).__name__}).", "Put a real site or a redirect on the sending domain; empty domains look like throwaway senders.", "low")
    order = {"high": 0, "medium": 1, "low": 2}
    r["fixes"].sort(key=lambda f: order.get(f["severity"], 3))
    return r

if __name__ == "__main__":
    res = audit(sys.argv[1].lower().strip())
    if "--json" in sys.argv: print(json.dumps(res, indent=1)); sys.exit()
    print(f"# Deliverability audit: {res['domain']} ({res['date']})\n")
    for c in res["checks"]: print(f"- [{c['status'].upper()}] {c['area']}: {c['detail']}")
    print("\n## Fixes, highest priority first")
    for i, f in enumerate(res["fixes"], 1): print(f"{i}. ({f['severity']}) {f['area']}: {f['fix']}")
    if not res["fixes"]: print("No fixes required.")
