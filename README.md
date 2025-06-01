# 🛡️ Website Security Analyzer — Python CLI Tool for Secure Web Development

> 🔗 Built by [Md Anik Hossen — CodeByAnik](https://codebyanik.com)  
> 💼 Laravel Developer | AI Enthusiast | Security Researcher  
> 📫 mdanikhossen999@gmail.com | 💻 Portfolio: [codebyanik.com](https://codebyanik.com)

---

## 🔍 Overview

**Website Security Analyzer** is an open-source Python tool that analyzes the basic security posture of any website by scanning its HTTPS status, SSL certificate, HTTP response, and key security headers. Designed for developers, freelancers, and security enthusiasts who want **quick insights and client-ready reports**.

---

## 🚀 Key Features

| Feature                        | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| ✅ HTTPS Check                | Detects if the website uses a secure HTTPS connection                       |
| 🔐 SSL Certificate Analyzer  | Shows SSL issuer, subject, and validity dates                               |
| 🌐 HTTP Status Code          | Confirms if the site is reachable (e.g., 200 OK, 404, etc.)                 |
| 🧱 Security Headers Scan     | Detects key headers like `CSP`, `HSTS`, `X-Frame-Options`, `XSS-Protection` |
| ⚡ Lightweight CLI Tool      | No browser, no heavy frameworks — pure Python                               |
| 📦 Easily Extendable         | Add AI, UI (Flask), reporting, or CI/CD integration                         |

---

## 🖼️ Sample Output

```bash
🔍 Scanning: https://codebyanik.com
----------------------------------------
🔐 HTTPS Enabled: Yes

📜 SSL Certificate Info:
   Issuer: CN=R10,O=Let's Encrypt,C=US
   Subject: CN=codebyanik.com
   Valid From: 2025-03-18 07:34:38
   Valid Until: 2025-06-16 07:34:37

🧱 Security Headers:
   ❌ Content-Security-Policy: Not set
   ❌ Strict-Transport-Security: Not set
   ✅ X-Content-Type-Options: nosniff
   ✅ X-Frame-Options: SAMEORIGIN
   ✅ X-XSS-Protection: 1; mode=block

🌐 HTTP Status: 200
```


