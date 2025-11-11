# Advanced Vulnerability Scanner - Complete Package

## 📦 What's Included

Your complete professional vulnerability scanner package with **234+ payloads** and comprehensive documentation.

---

## 📂 Files Overview

### Core Files

1. **vuln_scanner.py** (Main Tool - ~500 lines)
   - `PayloadDatabase` class: 234+ exploits for 8 vulnerability types
   - `TechDetector` class: Automatic technology fingerprinting
   - `VulnScanner` class: Core scanning engine
   - Interactive CLI menu system
   - JSON report generation

2. **VULN_SCANNER_README.md** (Main Documentation)
   - Complete usage guide
   - Vulnerability explanations
   - Payload databases
   - Default credentials
   - GET/POST examples
   - Troubleshooting

3. **scanner_examples.py** (13 Advanced Examples)
   - SQL injection testing
   - XSS detection
   - Technology fingerprinting
   - SSRF exploitation
   - NoSQL injection
   - Code injection
   - WAF bypass techniques
   - Multiple target scanning

---

## 🚀 Quick Start (3 Steps)

### Step 1: Install Dependencies
```bash
pip install requests
```

### Step 2: Run Interactive Scanner
```bash
python vuln_scanner.py
```

### Step 3: Follow Menu
```
[*] Enter target URL: http://your-site.com
[*] Select vulnerability type: 1-9
[*] Enter parameter: id
[*] Select method: GET or POST
```

---

## 💾 Payload Database: 234+ Total

### SQL Injection (40 payloads)
```
✓ Basic injection (OR 1=1, etc)
✓ Time-based blind (SLEEP, WAITFOR)
✓ Boolean-based blind
✓ Error-based (extractvalue, updatexml)
✓ Stacked queries (INSERT, UPDATE, DROP)
✓ Advanced UNION-based
✓ Database-specific (MySQL, PostgreSQL, Oracle, MongoDB)
```

### XSS - Cross-Site Scripting (38 payloads)
```
✓ Basic script injection
✓ Event handlers (onerror, onload, onfocus)
✓ Encoded variants (HTML, URL, Unicode)
✓ Case mutations
✓ SVG-based vectors
✓ HTML5 specific
✓ Polyglot payloads
✓ Attribute breaking
✓ Creative/advanced techniques
```

### SSRF - Server-Side Request Forgery (27 payloads)
```
✓ Localhost variations (127.0.0.1, ::1, etc)
✓ Internal IP ranges (192.168.x.x, 10.x.x.x)
✓ Cloud metadata endpoints
✓ Localhost bypass techniques
✓ Protocol tricks (gopher, file, dict)
✓ Filter evasion
```

### Code Injection & RCE (32 payloads)
```
✓ Command injection (;, |, &&, backticks)
✓ PHP shells (?php system, eval, assert)
✓ Python execution (__import__, exec, eval)
✓ Node.js/JavaScript
✓ Java Runtime.exec
✓ Perl backticks/system
✓ Template injection ({{7*7}}, ${}, <%, etc)
✓ Expression Language injection
```

### NoSQL Injection (16 payloads)
```
✓ MongoDB basic ($ne, $gt, $where)
✓ MongoDB advanced (regex, exists, nin)
✓ MongoDB blind injection
✓ CouchDB queries
✓ Firebase payloads
```

### Directory Traversal (25 payloads)
```
✓ Basic traversal (../, ..\\)
✓ URL encoding bypass
✓ Null byte injection (%00)
✓ Unicode encoding
✓ Windows paths
✓ Linux/Unix paths
✓ Application-specific (/config, /.env, /web.config)
```

### WAF Bypass (23 payloads)
```
✓ Case variation
✓ Encoding techniques
✓ Comment injection (/**/selec*t/*/)
✓ Whitespace tricks (%09, %0a, %0d)
✓ Polyglot payloads
✓ Filter evasion
✓ Unicode escaping
✓ Null byte injection
```

### Default Credentials (33 credentials)
```
✓ Web servers (admin, root, test)
✓ CMS: WordPress, Drupal, Joomla
✓ Databases: MySQL, PostgreSQL, Oracle, MongoDB, MSSQL
✓ SSH: root, admin, debian, ubuntu
✓ FTP servers
✓ Mail servers
✓ Routers
```

---

## 🔬 Key Features

### 1. Automatic Technology Detection
Detects:
- Web servers (Apache, Nginx, IIS)
- Programming languages (PHP, Python, Java, Node.js)
- CMS platforms (WordPress, Drupal, Joomla)
- Frameworks (Django, Laravel, Rails, Express)
- Databases (MySQL, PostgreSQL, MongoDB)
- Libraries & versions

### 2. Interactive Scanner
```
SELECT VULNERABILITY TYPE:
1. SQL Injection
2. XSS (Cross-Site Scripting)
3. SSRF (Server-Side Request Forgery)
4. Code Injection / RCE
5. NoSQL Injection
6. Directory Traversal
7. Default Credentials
8. Generate Report
9. Exit
```

### 3. Flexible Testing
- **GET requests**: URL parameter testing
- **POST requests**: Form and API testing
- **Parameter selection**: Test specific parameters
- **Custom payloads**: Extend payload database

### 4. Reporting
- JSON export with full details
- Vulnerability categorization
- Payload information
- HTTP status codes
- Timestamps

---

## 📖 Usage Examples

### Example 1: Test Search Parameter for SQLi
```bash
$ python vuln_scanner.py

[*] Target URL: http://shop.example.com/search.php
[*] Select: 1 (SQL Injection)
[*] Parameter: q
[*] Method: GET

# Tests URLs like:
# http://shop.example.com/search.php?q=' OR '1'='1
# http://shop.example.com/search.php?q='; DROP TABLE products; --
```

### Example 2: Test Login for XSS
```bash
[*] Target URL: http://example.com/login.php
[*] Select: 2 (XSS)
[*] Parameter: username
[*] Method: POST

# POSTs data like:
# username=<script>alert('XSS')</script>&password=test
# username=<img src=x onerror=alert('XSS')>&password=test
```

### Example 3: Test Image Proxy for SSRF
```bash
[*] Target URL: http://example.com/image.php
[*] Select: 3 (SSRF)
[*] Parameter: url
[*] Method: GET

# Tests URLs like:
# http://example.com/image.php?url=http://localhost/admin
# http://example.com/image.php?url=http://169.254.169.254/latest/meta-data/
```

### Example 4: Programmatic Usage
```python
from vuln_scanner import VulnScanner, PayloadDatabase

scanner = VulnScanner("http://example.com")
results = scanner.scan_sql_injection("id", method="GET")

for vuln in results:
    print(f"Found: {vuln['payload']}")

scanner.generate_report(results)
```

---

## 🎯 Testing Checklist

### Before Scanning
- [ ] Have written authorization
- [ ] Define scope (which URLs/parameters)
- [ ] Know target tech stack
- [ ] Have backup access method
- [ ] Schedule during agreed time

### During Scanning
- [ ] Monitor target performance
- [ ] Log all tests
- [ ] Don't modify data
- [ ] Stay within scope
- [ ] Use consistent tool version

### After Scanning
- [ ] Document findings
- [ ] Provide remediation steps
- [ ] Clean up test data
- [ ] Maintain confidentiality
- [ ] Follow up with vendor

---

## 🔐 Security Notes

### For Testers
✓ **Always get authorization** before testing
✓ **Test carefully** to avoid data loss or service disruption
✓ **Document everything** for legal protection
✓ **Keep findings confidential** - don't share with others
✓ **Delete test data** after testing

### For Defenders
✓ Use parameterized queries (prevents SQLi)
✓ Sanitize all inputs (prevents XSS, injection)
✓ Validate output encoding (prevents XSS)
✓ Use WAF rules strategically
✓ Monitor for suspicious activity
✓ Keep software updated
✓ Use strong default credentials
✓ Implement proper authentication

---

## 📊 Statistics

| Metric | Value |
|--------|-------|
| Total Payloads | 234 |
| SQL Injection Variants | 40 |
| XSS Variants | 38 |
| SSRF Payloads | 27 |
| Code Injection Payloads | 32 |
| NoSQL Injection Payloads | 16 |
| Directory Traversal Payloads | 25 |
| WAF Bypass Techniques | 23 |
| Default Credentials | 33 |
| Vulnerability Types | 8 |
| Lines of Code | ~500 |

---

## 🛠️ Advanced Usage

### Get All SQL Injection Payloads
```python
from vuln_scanner import PayloadDatabase

sqli = PayloadDatabase.get_sql_injection_payloads()
# Returns dict with categories: basic, time_based, error_based, etc.
```

### Get Specific Payload Category
```python
xss = PayloadDatabase.get_xss_payloads()
events = xss['event_handlers']  # 5 payloads
encoded = xss['encoded']        # 5 payloads
```

### Scan Multiple Parameters
```python
params = ['id', 'name', 'email', 'search']
for param in params:
    results = scanner.scan_xss(param)
    if results:
        print(f"{param} is vulnerable!")
```

### Batch Scanning
```python
targets = ['http://site1.com', 'http://site2.com']
for target in targets:
    scanner = VulnScanner(target)
    results = scanner.scan_sql_injection('id')
    scanner.generate_report(results, f"{target}.json")
```

---

## 🐛 Troubleshooting

### Connection Timeout
**Problem:** Target doesn't respond
**Solution:** Check URL, verify internet, increase timeout

### No Vulnerabilities Found
**Reasons:**
- Target is actually secure (good!)
- WAF is blocking tests
- Detection needs tuning
- Test with simple payload manually

### False Positives
**Solution:** Always manually verify findings

### Blocked by WAF
**Try:**
- WAF bypass payloads (option in menu)
- Test with different encoding
- Change case variation
- Try comment injection

---

## 📚 Learning Resources

### OWASP Top 10 Vulnerabilities
1. SQL Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. XML External Entities (XXE)
5. Broken Access Control
6. Security Misconfiguration
7. Cross-Site Scripting (XSS)
8. Insecure Deserialization
9. Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring

### Recommended Study Topics
- OWASP Testing Guide
- PortSwigger Web Security Academy
- HackTheBox labs
- TryHackMe rooms
- Bug bounty reports

---

## 🎓 Files Breakdown

```
THM-CODE-VULN/
├── vuln_scanner.py              # Main scanner (500 lines)
├── VULN_SCANNER_README.md       # Complete documentation
├── scanner_examples.py          # 13 working examples
├── password_generator.py        # (Included from before)
├── example_usage.py             # (Included from before)
└── README.md                    # (Main project readme)
```

---

## ✅ Verification Checklist

- [x] 234+ payloads implemented
- [x] SQL Injection (8 categories)
- [x] XSS (9 categories)
- [x] SSRF (6 categories)
- [x] Code Injection (8 categories)
- [x] NoSQL Injection (5 categories)
- [x] Directory Traversal (7 categories)
- [x] WAF Bypass (8 categories)
- [x] Default Credentials (9 categories, 33 total)
- [x] Technology Detection (headers, cookies, content, fingerprints, paths)
- [x] Interactive CLI menu
- [x] GET/POST support
- [x] JSON reporting
- [x] Comprehensive documentation
- [x] Working examples
- [x] Programmatic API

---

## 🚀 Getting Started Now

### Quick Commands

```bash
# Install dependencies
pip install requests

# Run interactive scanner
python vuln_scanner.py

# Run examples
python scanner_examples.py

# Programmatic use
python
>>> from vuln_scanner import VulnScanner
>>> scanner = VulnScanner("http://target.com")
>>> results = scanner.scan_sql_injection("id")
```

---

## 📞 Support

### Need Help?
1. Check `VULN_SCANNER_README.md` - Comprehensive guide
2. Run `scanner_examples.py` - See working examples
3. Review payload categories - Understand attack types
4. Read source code - Well-commented

### Common Questions Answered In:
- **How to use:** `VULN_SCANNER_README.md` - Usage Guide section
- **Payloads:** `PayloadDatabase` class in `vuln_scanner.py`
- **Examples:** `scanner_examples.py` - 13 practical examples
- **Tech detection:** `TechDetector` class

---

## ⚖️ Legal & Ethics

### Remember:
✅ **Authorized Testing Only** - Get written permission
✅ **Scope Definition** - Know what you can test
✅ **Professional Conduct** - Follow ethical guidelines
✅ **Confidentiality** - Keep findings private
✅ **Legal Compliance** - Follow local laws

### Unauthorized Access is Illegal:
❌ Unauthorized system access = Federal crime (CFAA, UK Computer Misuse Act)
❌ Data theft = Criminal liability + civil liability
❌ System damage = Felony charges

---

## 🎉 You're Ready!

Your advanced vulnerability scanner is fully equipped with:
- ✅ 234+ payloads
- ✅ 8 vulnerability types
- ✅ Technology detection
- ✅ Interactive menu
- ✅ Professional reporting
- ✅ Complete documentation
- ✅ Working examples

**Start with:** `python vuln_scanner.py`

---

## 📝 Version Info

- **Version:** 1.0
- **Status:** Production Ready
- **Last Updated:** January 2024
- **Total Payloads:** 234
- **Vulnerability Types:** 8
- **Default Credentials:** 33

---

**Remember: Test Responsibly. Test Legally. Test Ethically.** 🔐

For questions, always refer to `VULN_SCANNER_README.md` for detailed information.
