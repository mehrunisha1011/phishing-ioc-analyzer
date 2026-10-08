from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timezone
import os

OUT = os.path.join(os.path.dirname(__file__), "..", "Sample_Data")
os.makedirs(OUT, exist_ok=True)

def base(frm, to, subj, reply_to=None):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = to
    m["Subject"] = subj
    m["Date"] = format_datetime(datetime.now(timezone.utc))
    m["Message-ID"] = "<synthetic-%s@lab.test>" % abs(hash(subj))
    if reply_to:
        m["Reply-To"] = reply_to
    return m

def save(m, name):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(bytes(m))

# --- 1. credential phishing, no attachment ---
m = base('"PayPal Security" <security@paypa1-secure.example>',
         "victim@corp.test",
         "Urgent: Your account has been limited",
         reply_to="support-desk@mail-gateway.example")
m.add_header("Received", "from mail-gateway.example (unknown [203.0.113.45]) by mx.corp.test with ESMTP; Thu, 08 Oct 2026 02:10:00 +0000")
m.add_header("Received", "from [198.51.100.7] (helo=localhost) by mail-gateway.example; Thu, 08 Oct 2026 02:09:58 +0000")
m["X-Originating-IP"] = "198.51.100.7"
m["Authentication-Results"] = "mx.corp.test; spf=fail smtp.mailfrom=paypa1-secure.example; dkim=none; dmarc=fail header.from=paypa1-secure.example"
m.set_content("Your account is limited. Verify now: http://paypa1-secure.example/verify?id=88123\nOr use http://203.0.113.45/login.php")
m.add_alternative('<html><body><p>Your account is limited.</p><a href="http://paypa1-secure.example/verify?id=88123">https://www.paypal.com/verify</a></body></html>', subtype="html")
save(m, "phish1_credential.eml")

# --- 2. invoice phishing with attachment ---
m = base('"Accounts Dept" <billing@invoice-center.example>',
         "victim@corp.test",
         "Invoice 8841 overdue - open attached",
         reply_to="billing@invoice-center.example")
m.add_header("Received", "from smtp.invoice-center.example ([192.0.2.99]) by mx.corp.test with ESMTP; Thu, 08 Oct 2026 03:30:00 +0000")
m["Authentication-Results"] = "mx.corp.test; spf=softfail smtp.mailfrom=invoice-center.example; dkim=fail; dmarc=fail"
m.set_content("Please see the attached invoice. Pay at https://pay.invoice-center.example/inv/8841 within 24h.")
m.add_attachment(b"DUMMY-SAMPLE-NOT-A-REAL-FILE", maintype="application", subtype="octet-stream", filename="Invoice_8841.pdf.exe")
save(m, "phish2_invoice.eml")

# --- 3. benign ---
m = base('"Example News" <newsletter@example.org>',
         "victim@corp.test",
         "Your weekly digest")
m.add_header("Received", "from mail.example.org ([192.0.2.10]) by mx.corp.test with ESMTP; Thu, 08 Oct 2026 04:00:00 +0000")
m["Authentication-Results"] = "mx.corp.test; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass header.from=example.org"
m.set_content("Read this week's stories: https://www.example.org/news/weekly")
save(m, "benign_newsletter.eml")

print("samples written to", os.path.abspath(OUT))
