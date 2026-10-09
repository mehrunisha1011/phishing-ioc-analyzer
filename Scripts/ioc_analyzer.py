#!/usr/bin/env python3
import argparse, difflib, email, hashlib, json, re
from datetime import datetime
from email import policy
from email.utils import parseaddr
from html import escape
from urllib.parse import urlparse

URL_RE   = re.compile(r'https?://[^\s"\'<>\)\]]+', re.I)
IPV4_RE  = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')

def addr_domain(value):
    addr = parseaddr(value or "")[1]
    return addr.split("@")[-1].lower() if "@" in addr else ""

def get_bodies(msg):
    plain, html = "", ""
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ct = part.get_content_type()
        if ct == "text/plain":
            plain += part.get_content()
        elif ct == "text/html":
            html += part.get_content()
    return plain, html

def parse_auth(msg):
    ar = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    out = {}
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(r'\b%s=(\w+)' % k, ar, re.I)
        out[k] = m.group(1).lower() if m else "none"
    return out

def header_ips(msg):
    ips = []
    for h in msg.get_all("Received", []):
        ips += IPV4_RE.findall(str(h))
    xo = msg.get("X-Originating-IP")
    if xo:
        ips += IPV4_RE.findall(str(xo))
    return ips

def hash_bytes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "maybank": ["maybank.com", "maybank2u.com.my"],
}

def normalize_variants(token):
    base = token.lower().replace("rn", "m").replace("vv", "w")
    out = set()
    for one in ("l", "i"):
        table = str.maketrans({"0": "o", "1": one, "3": "e", "4": "a", "5": "s", "$": "s"})
        out.add(base.translate(table))
    return out

def lookalike_flags(domains):
    found = []
    for d in domains:
        if any(d == off or d.endswith("." + off) for offs in BRANDS.values() for off in offs):
            continue
        labels = d.split(".")[:-1] or [d]
        tokens = [t for lab in labels for t in lab.split("-") if t]
        for brand in BRANDS:
            for tok in tokens:
                if tok == brand:
                    found.append("Brand name '%s' used in unofficial domain (%s)" % (brand, d))
                    break
                variants = normalize_variants(tok)
                close = len(tok) >= 5 and any(
                    difflib.SequenceMatcher(None, v, brand).ratio() >= 0.85 for v in variants)
                if brand in variants or close:
                    found.append("Look-alike domain: %s imitates '%s'" % (d, brand))
                    break
    return found

def risk_score(r):
    """Score 0-100 from authentication results and detection flags."""
    score = 0
    for k, w in (("spf", 15), ("dkim", 10), ("dmarc", 15)):
        v = r["authentication"].get(k, "none")
        if v == "fail":
            score += w
        elif v != "pass":          # softfail / none / neutral
            score += w // 2
    for f in r["flags"]:
        if f.startswith("Reply-To"):
            score += 15
        elif "raw IP" in f:
            score += 20
        elif "double extension" in f:
            score += 35
        elif "Look-alike" in f or "Brand name" in f:
            score += 20
    score = min(score, 100)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    return score, level

def analyze(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    plain, html = get_bodies(msg)
    body = plain + "\n" + html

    urls = sorted(set(u.rstrip(".,;") for u in URL_RE.findall(body)))
    domains, body_ips = set(), set(IPV4_RE.findall(body))
    for u in urls:
        host = urlparse(u).hostname or ""
        if IPV4_RE.fullmatch(host):
            body_ips.add(host)
        elif host:
            domains.add(host.lower())
    for a in EMAIL_RE.findall(str(msg["From"]) + " " + str(msg["Reply-To"]) + " " + body):
        domains.add(a.split("@")[-1].lower())

    attachments = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        attachments.append({"filename": part.get_filename(),
                            "content_type": part.get_content_type(),
                            "size": len(data), **hash_bytes(data)})

    auth = parse_auth(msg)
    from_dom, reply_dom = addr_domain(msg["From"]), addr_domain(msg["Reply-To"])

    flags = []
    if reply_dom and reply_dom != from_dom:
        flags.append("Reply-To domain (%s) differs from From domain (%s)" % (reply_dom, from_dom))
    for k, v in auth.items():
        if v != "pass":
            flags.append("%s result is '%s'" % (k.upper(), v))
    if any(a["filename"] and a["filename"].lower().count(".") >= 2 for a in attachments):
        flags.append("Attachment has double extension")
    if any(IPV4_RE.fullmatch(urlparse(u).hostname or "") for u in urls):
        flags.append("URL points to a raw IP address")

    flags += lookalike_flags(sorted(domains))

    result = {
        "file": path,
        "from": str(msg["From"]),
        "reply_to": str(msg["Reply-To"]) if msg["Reply-To"] else None,
        "subject": str(msg["Subject"]),
        "date": str(msg["Date"]),
        "message_id": str(msg["Message-ID"]),
        "received_chain": [" ".join(str(h).split()) for h in msg.get_all("Received", [])],
        "header_ips": sorted(set(header_ips(msg))),
        "authentication": auth,
        "urls": urls,
        "domains": sorted(domains),
        "body_ips": sorted(body_ips),
        "attachments": attachments,
        "flags": flags,
    }
    result["risk_score"], result["risk_level"] = risk_score(result)
    return result

def summary(r):
    print("=" * 60)
    print("FILE     :", r["file"])
    print("FROM     :", r["from"])
    print("REPLY-TO :", r["reply_to"])
    print("SUBJECT  :", r["subject"])
    print("AUTH     :", r["authentication"])
    print("HDR IPs  :", ", ".join(r["header_ips"]) or "-")
    print("URLS     :", *r["urls"], sep="\n   ") if r["urls"] else print("URLS     : -")
    print("DOMAINS  :", ", ".join(r["domains"]) or "-")
    print("BODY IPs :", ", ".join(r["body_ips"]) or "-")
    for a in r["attachments"]:
        print("ATTACH   : %s  sha256=%s" % (a["filename"], a["sha256"]))
    print("FLAGS    :", *r["flags"], sep="\n   [!] ") if r["flags"] else print("FLAGS    : none")
    print("RISK     : %d/100 (%s)" % (r["risk_score"], r["risk_level"]))

def write_html(results, path):
    colors = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#22c55e"}

    def row(label, items):
        if not items:
            return ""
        cells = "".join("<code>%s</code>" % escape(str(i)) for i in items)
        return "<tr><th>%s</th><td>%s</td></tr>" % (label, cells)

    cards = []
    for r in results:
        c = colors[r["risk_level"]]
        flags = "".join("<li>%s</li>" % escape(f) for f in r["flags"]) \
            or "<li class='ok'>No suspicious indicators found</li>"
        auth = "".join(
            "<span class='pill %s'>%s: %s</span>" %
            ("good" if v == "pass" else "bad", k.upper(), escape(v))
            for k, v in r["authentication"].items())
        atts = ["%s (sha256: %s)" % (a["filename"], a["sha256"]) for a in r["attachments"]]
        iocs = (row("Header IPs", r["header_ips"]) + row("Body IPs", r["body_ips"]) +
                row("Domains", r["domains"]) + row("URLs", r["urls"]) + row("Attachments", atts))
        cards.append("""
<section class="card" style="border-top:4px solid %s">
  <div class="head">
    <div><h2>%s</h2><p class="muted">%s</p></div>
    <div class="score" style="color:%s">%d<small>/100</small><span>%s RISK</span></div>
  </div>
  <p><b>From:</b> %s<br><b>Reply-To:</b> %s</p>
  <div>%s</div>
  <h3>Flags</h3><ul class="flags">%s</ul>
  <h3>Extracted IOCs</h3><table>%s</table>
</section>""" % (c, escape(r["subject"]), escape(r["file"]), c, r["risk_score"],
                 r["risk_level"], escape(r["from"]), escape(str(r["reply_to"])), auth, flags, iocs))

    counts = {lvl: sum(1 for r in results if r["risk_level"] == lvl) for lvl in colors}
    stats = "".join(
        "<div class='stat'><b style='color:%s'>%d</b><span>%s</span></div>" % (colors[l], n, l)
        for l, n in counts.items())

    page = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing IOC Report</title>
<style>
body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.5 system-ui,Segoe UI,sans-serif;padding:32px}
.wrap{max-width:980px;margin:auto}
h1{margin:0 0 4px;font-size:28px} .muted{color:#8b949e;margin:2px 0}
.stats{display:flex;gap:14px;margin:20px 0}
.stat{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px 22px;text-align:center}
.stat b{display:block;font-size:28px} .stat span{color:#8b949e;font-size:12px;letter-spacing:1px}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:22px;margin:18px 0}
.head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}
.head h2{margin:0;font-size:19px}
.score{font-size:44px;font-weight:700;text-align:right;line-height:1}
.score small{font-size:16px;color:#8b949e} .score span{display:block;font-size:12px;letter-spacing:2px}
.pill{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;margin:2px 6px 2px 0}
.pill.good{background:#12351f;color:#3fb950} .pill.bad{background:#3d1418;color:#f85149}
h3{font-size:13px;letter-spacing:1px;text-transform:uppercase;color:#8b949e;margin:18px 0 6px}
.flags{margin:0;padding-left:20px;color:#f0883e} .flags .ok{color:#3fb950}
table{width:100%%;border-collapse:collapse} th{width:110px;text-align:left;color:#8b949e;vertical-align:top;padding:5px 0;font-weight:500}
td{padding:5px 0} code{display:inline-block;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:1px 8px;margin:2px 6px 2px 0;font-size:12.5px;word-break:break-all}
footer{color:#8b949e;font-size:12px;text-align:center;margin-top:30px}
</style></head><body><div class="wrap">
<h1>🛡️ Phishing IOC Report</h1>
<p class="muted">Generated %s &middot; %d email(s) analyzed &middot; synthetic samples only</p>
<div class="stats">%s</div>
%s
<footer>Phishing Email &amp; IOC Analyzer &middot; github.com/mehrunisha1011/phishing-ioc-analyzer</footer>
</div></body></html>""" % (datetime.now().strftime("%Y-%m-%d %H:%M"), len(results), stats, "".join(cards))
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Phishing email IOC analyzer")
    ap.add_argument("eml", nargs="+")
    ap.add_argument("-j", "--json", help="write JSON report to this file")
    ap.add_argument("--html", help="write a visual HTML report to this file")
    args = ap.parse_args()
    results = [analyze(p) for p in args.eml]
    for r in results:
        summary(r)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print("\nJSON report written to", args.json)
    if args.html:
        write_html(results, args.html)
        print("HTML report written to", args.html)
