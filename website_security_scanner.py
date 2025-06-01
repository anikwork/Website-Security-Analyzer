import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def check_https(url):
    return url.startswith("https://")


def get_ssl_info(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert(binary_form=True)
            x509_cert = x509.load_der_x509_certificate(cert, default_backend())
            return {
                "issuer": x509_cert.issuer.rfc4514_string(),
                "subject": x509_cert.subject.rfc4514_string(),
                "not_valid_before": x509_cert.not_valid_before_utc,
                "not_valid_after": x509_cert.not_valid_after_utc,

            }


def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        important_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection"
        ]
        found_headers = {h: headers.get(h) for h in important_headers}
        return found_headers
    except Exception as e:
        return {"error": str(e)}


def check_status_code(url):
    try:
        r = requests.get(url, timeout=5)
        return r.status_code
    except Exception as e:
        return str(e)


def analyze_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname

    print(f"\n🔍 Scanning: {url}")
    print(f"{'-'*40}")
    print(f"🔐 HTTPS Enabled: {'Yes' if check_https(url) else 'No'}")

    try:
        ssl_info = get_ssl_info(domain)
        print("📜 SSL Certificate Info:")
        print(f"   Issuer: {ssl_info['issuer']}")
        print(f"   Subject: {ssl_info['subject']}")
        print(f"   Valid From: {ssl_info['not_valid_before']}")
        print(f"   Valid Until: {ssl_info['not_valid_after']}")
    except Exception as e:
        print(f"❌ Could not fetch SSL info: {e}")

    headers = check_security_headers(url)
    print("\n🧱 Security Headers:")
    for key, value in headers.items():
        if value:
            print(f"   ✅ {key}: {value}")
        else:
            print(f"   ❌ {key}: Not set")

    status = check_status_code(url)
    print(f"\n🌐 HTTP Status: {status}")
    print(f"{'-'*40}")


# Example usage
if __name__ == "__main__":
    input_url = input("Enter website URL (e.g., https://example.com): ").strip()
    if not input_url.startswith("http"):
        input_url = "https://" + input_url
    analyze_url(input_url)
