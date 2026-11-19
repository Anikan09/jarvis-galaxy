"""Demo mode: made-up OSINT results, so a screenshot never shows a real lookup."""
from modules.security.common import finding, report, row


def result(kind, value):
    if kind == "file":
        f = [finding("high", "GPS position: 51.507400, -0.127800"), finding("medium", "Camera serial number: SN-4471-0099")]
        return report("metadata", "Metadata check", value.replace("\\", "/").split("/")[-1], "reveals details",
                      [{"title": "Metadata", "rows": [row("GPS position", "51.507400, -0.127800", "high"), row("Camera serial number", "SN-4471-0099", "medium"),
                                                      row("Camera model", "Pixel 8"), row("Taken", "2026:11:02 08:14:51", "low")]}], f,
                      "Before you share that, it gives away its GPS position and camera serial number.", badge="LOCAL ONLY")
    if kind == "ip":
        return report("ip", "IP intel", value, "looked up", [{"title": "Who runs it", "rows": [row("Address", value), row("Reverse DNS", "edge-12.example-cdn.net"),
                      row("Org", "Example CDN Ltd"), row("Country", "NL")]}], [], f"{value} belongs to Example CDN Ltd in NL.", badge="PASSIVE")
    return report("domain", "Domain recon", value, "worth a look", [
        {"title": "Registration (RDAP)", "rows": [row("Registrar", "Example Registrar Inc."), row("Registered", "2026-11-04"), row("DNSSEC", "unsigned")]},
        {"title": "DNS records", "rows": [row("A", "203.0.113.20"), row("MX", "10 mail.example.net"), row("DMARC", "missing")]},
        {"title": "TLS certificate", "rows": [row("Issuer", "Let's Encrypt"), row("Valid until", "2027-02-02 (75 days)")]}],
        [finding("medium", "The domain was registered only 15 days ago. Brand-new domains are a common sign of phishing."),
         finding("medium", "No DMARC policy: receivers aren't told what to do with forged mail.")],
        f"The recon on {value} is in the drawer. Worth a look: the domain was registered only 15 days ago.", badge="PASSIVE")
