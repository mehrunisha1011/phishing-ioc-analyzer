#!/usr/bin/env python3
import argparse, difflib, email, hashlib, json, re
from email import policy
from email.utils import parseaddr
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

    return {
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

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Phishing email IOC analyzer")
    ap.add_argument("eml", nargs="+")
    ap.add_argument("-j", "--json", help="write JSON report to this file")
    args = ap.parse_args()
    results = [analyze(p) for p in args.eml]
    for r in results:
        summary(r)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print("\nJSON report written to", args.json)
