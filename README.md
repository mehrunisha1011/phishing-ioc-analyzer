## Findings

| Sample | Verdict | Key indicators |
|---|---|---|
| phish1_credential.eml | Malicious (credential phishing) | Look-alike domain `paypa1-secure.example` (the digit 1 instead of the letter l), Reply-To differs from From, SPF fail, DKIM none, DMARC fail, link to a raw IP (203.0.113.45) |
| phish2_invoice.eml | Malicious (malware delivery) | Attachment `Invoice_8841.pdf.exe` (double extension), SPF softfail, DKIM fail, DMARC fail |
| benign_newsletter.eml | Legitimate | SPF/DKIM/DMARC all pass, no flags |

**IOCs extracted**
- IPs: 203.0.113.45, 198.51.100.7, 192.0.2.99
- Domains: paypa1-secure.example, mail-gateway.example, invoice-center.example
- SHA-256 of the attachment: e4017d8342e180f652f3f8a329564fa4f6b5750af71380fe81c71e4d6dd2ac8b

**MITRE ATT&CK mapping**
- T1566.002: Phishing: Spearphishing Link (phish1)
- T1566.001: Phishing: Spearphishing Attachment (phish2)
- T1036.007: Masquerading: Double File Extension (phish2)

**Limitations:** The tool does not detect look-alike (typosquatted) domains yet, and VirusTotal enrichment is not implemented. These are planned improvements.

## Remediation: Block the listed domains/IPs at the mail gateway, quarantine emails with double-extension attachments, and enforce DMARC reject policy.
