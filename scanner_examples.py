"""
Advanced Vulnerability Scanner - Usage Examples & Advanced Guide
Demonstrates all features with detailed real-world scenarios
"""

from vuln_scanner import VulnScanner, PayloadDatabase, TechDetector
import json


def example_1_basic_sql_injection_test():
    """Example 1: Basic SQL Injection Testing"""
    print("\n" + "=" * 70)
    print("EXAMPLE 1: Basic SQL Injection Testing")
    print("=" * 70)

    # Target: http://example.com/user.php?id=1
    print("\n[*] Testing URL: http://example.com/user.php?id=1")
    print("[*] Suspected parameter: id")

    scanner = VulnScanner("http://example.com/user.php")

    # Test for SQL injection
    print("\n[*] Testing SQL Injection payloads...")
    results = scanner.scan_sql_injection(parameter="id", method="GET")

    print(f"\n[+] Test complete. Found {len(results)} potential vulnerabilities")

    if results:
        for i, vuln in enumerate(results[:3], 1):
            print(f"\n  [{i}] Category: {vuln['category']}")
            print(f"      Payload: {vuln['payload'][:80]}...")
            print(f"      Status: {vuln['status_code']}")


def example_2_xss_detection_forms():
    """Example 2: XSS Detection in Forms"""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: XSS Detection in Forms")
    print("=" * 70)

    print("\n[*] Target: http://blog.example.com/comment.php")
    print("[*] Testing parameter: comment")

    scanner = VulnScanner("http://blog.example.com/comment.php")

    # Get XSS payload categories
    xss_payloads = PayloadDatabase.get_xss_payloads()
    print(f"\n[+] Available XSS payload categories:")
    for category in xss_payloads.keys():
        count = len(xss_payloads[category])
        print(f"    - {category}: {count} payloads")

    # Scan for XSS
    print("\n[*] Scanning for XSS vulnerabilities...")
    results = scanner.scan_xss(parameter="comment", method="POST")

    print(f"[+] Found {len(results)} potential XSS vulnerabilities")


def example_3_technology_detection():
    """Example 3: Detecting Web Technologies"""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: Web Technology Detection")
    print("=" * 70)

    target = "http://example.com"
    print(f"\n[*] Detecting technologies for: {target}")

    scanner = VulnScanner(target)

    try:
        print("[*] Analyzing headers, cookies, and content...")
        tech = scanner.detect_technologies()

        print("\n[+] Detected Technologies:")
        for category, details in tech.items():
            if isinstance(details, dict) and details:
                print(f"\n    {category.upper()}:")
                for key, value in details.items():
                    print(f"      - {key}: {value}")
    except Exception as e:
        print(f"[!] Error during detection: {e}")
        print("[*] This is normal for localhost/non-responsive targets")


def example_4_ssrf_detection():
    """Example 4: SSRF Detection"""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: SSRF Detection")
    print("=" * 70)

    print("\n[*] Target: http://example.com/proxy.php?url=")
    print("[*] Testing parameter: url")

    scanner = VulnScanner("http://example.com/proxy.php")

    # Get SSRF payload categories
    ssrf_payloads = PayloadDatabase.get_ssrf_payloads()
    print(f"\n[+] SSRF Payload Categories:")
    for category, payloads in ssrf_payloads.items():
        print(f"    - {category}: {len(payloads)} payloads")

    # Show some example payloads
    print(f"\n[+] Example SSRF payloads:")
    print(f"    - {ssrf_payloads['localhost'][0]}")
    print(f"    - {ssrf_payloads['cloud_metadata'][0]}")
    print(f"    - {ssrf_payloads['bypass_localhost'][0]}")


def example_5_payload_database_access():
    """Example 5: Accessing Payload Database"""
    print("\n" + "=" * 70)
    print("EXAMPLE 5: Working with Payload Database")
    print("=" * 70)

    # Get all SQL injection payloads
    sql_payloads = PayloadDatabase.get_sql_injection_payloads()

    print("\n[+] SQL Injection Payloads - Basic Category:")
    for i, payload in enumerate(sql_payloads["basic"][:5], 1):
        print(f"    {i}. {payload}")

    # Get all XSS payloads
    xss_payloads = PayloadDatabase.get_xss_payloads()
    print(f"\n[+] XSS Payloads - Event Handlers Category:")
    for i, payload in enumerate(xss_payloads["event_handlers"][:3], 1):
        print(f"    {i}. {payload}")

    # Get directory traversal payloads
    dir_traversal = PayloadDatabase.get_directory_traversal_payloads()
    print(f"\n[+] Directory Traversal - Linux Category:")
    for i, payload in enumerate(dir_traversal["linux"][:3], 1):
        print(f"    {i}. {payload}")


def example_6_default_credentials():
    """Example 6: Default Credentials Database"""
    print("\n" + "=" * 70)
    print("EXAMPLE 6: Default Credentials Testing")
    print("=" * 70)

    creds = PayloadDatabase.get_default_credentials()

    print("\n[+] CMS - WordPress Defaults:")
    for username, password in creds["cms_wordpress"]:
        print(f"    - {username}:{password}")

    print(f"\n[+] Database - Default Credentials:")
    for username, password in creds["databases"][:5]:
        print(f"    - {username}:{password}")

    print(f"\n[+] SSH - Default Credentials:")
    for username, password in creds["ssh"]:
        print(f"    - {username}:{password}")


def example_7_code_injection_payloads():
    """Example 7: Code Injection Payloads"""
    print("\n" + "=" * 70)
    print("EXAMPLE 7: Code Injection Payloads")
    print("=" * 70)

    code_inj = PayloadDatabase.get_code_injection_payloads()

    print("\n[+] Command Injection Payloads:")
    for i, payload in enumerate(code_inj["command_injection"][:3], 1):
        print(f"    {i}. {payload}")

    print(f"\n[+] PHP Code Injection Payloads:")
    for i, payload in enumerate(code_inj["php"][:3], 1):
        print(f"    {i}. {payload}")

    print(f"\n[+] Python Code Injection Payloads:")
    for i, payload in enumerate(code_inj["python"][:3], 1):
        print(f"    {i}. {payload}")


def example_8_nosql_injection():
    """Example 8: NoSQL Injection Payloads"""
    print("\n" + "=" * 70)
    print("EXAMPLE 8: NoSQL Injection Payloads")
    print("=" * 70)

    nosql = PayloadDatabase.get_nosql_injection_payloads()

    print("\n[+] MongoDB Basic Payloads:")
    for i, payload in enumerate(nosql["mongodb_basic"][:4], 1):
        print(f"    {i}. {payload}")

    print(f"\n[+] MongoDB Advanced Payloads:")
    for i, payload in enumerate(nosql["mongodb_advanced"][:3], 1):
        print(f"    {i}. {payload}")

    print(f"\n[+] MongoDB Blind Injection:")
    for i, payload in enumerate(nosql["mongodb_blind"][:2], 1):
        print(f"    {i}. {payload}")


def example_9_waf_bypass():
    """Example 9: WAF Bypass Techniques"""
    print("\n" + "=" * 70)
    print("EXAMPLE 9: WAF Bypass Payloads")
    print("=" * 70)

    waf = PayloadDatabase.get_waf_bypass_payloads()

    print("\n[+] WAF Bypass - Case Variation:")
    for payload in waf["case_variation"][:2]:
        print(f"    {payload}")

    print(f"\n[+] WAF Bypass - Comment Injection:")
    for payload in waf["comment_injection"][:2]:
        print(f"    {payload}")

    print(f"\n[+] WAF Bypass - Whitespace Tricks:")
    for payload in waf["whitespace_variations"][:2]:
        print(f"    {payload}")

    print(f"\n[+] WAF Bypass - Filter Evasion:")
    for payload in waf["filter_evasion"][:3]:
        print(f"    {payload}")


def example_10_multiple_targets():
    """Example 10: Scanning Multiple Targets"""
    print("\n" + "=" * 70)
    print("EXAMPLE 10: Scanning Multiple Targets")
    print("=" * 70)

    targets = [
        "http://site1.example.com/search.php",
        "http://site2.example.com/query.php",
        "http://site3.example.com/find.php",
    ]

    all_results = []

    for target in targets:
        print(f"\n[*] Scanning: {target}")
        try:
            scanner = VulnScanner(target)
            results = scanner.scan_sql_injection("q", method="GET")
            all_results.extend(results)
            print(f"    [+] Found {len(results)} potential vulnerabilities")
        except Exception as e:
            print(f"    [-] Error: {e}")

    print(f"\n[+] Total vulnerabilities across all targets: {len(all_results)}")


def example_11_programmatic_scanning():
    """Example 11: Programmatic Use"""
    print("\n" + "=" * 70)
    print("EXAMPLE 11: Programmatic Scanning")
    print("=" * 70)

    print("\n[*] Example: Custom scanning script")

    code = """
from vuln_scanner import VulnScanner

scanner = VulnScanner("http://vulnerable-app.local")

# Test multiple parameters
params = ['id', 'search', 'name', 'email']
vulns = {}

for param in params:
    print(f'Testing {param}...')
    results = scanner.scan_sql_injection(param, method='GET')
    if results:
        vulns[param] = results

# Generate report
report = {
    'target': 'http://vulnerable-app.local',
    'vulnerabilities': vulns
}

import json
with open('report.json', 'w') as f:
    json.dump(report, f, indent=2)
"""

    print(code)


def example_12_get_vs_post():
    """Example 12: GET vs POST Testing"""
    print("\n" + "=" * 70)
    print("EXAMPLE 12: GET vs POST Testing")
    print("=" * 70)

    scanner = VulnScanner("http://example.com/login.php")

    print("\n[*] GET Request Test:")
    print("    URL: http://example.com/login.php?username=admin")
    print("    Scanner sends: http://example.com/login.php?username=PAYLOAD")

    print("\n[*] POST Request Test:")
    print("    URL: http://example.com/login.php")
    print("    Scanner sends POST body: username=PAYLOAD&password=...")

    print("\n[*] When to use GET:")
    print("    - Query parameters")
    print("    - URL-based testing")
    print("    - Search functionality")

    print("\n[*] When to use POST:")
    print("    - Login forms")
    print("    - File uploads")
    print("    - Data submission")
    print("    - API endpoints")


def example_13_payload_statistics():
    """Example 13: Payload Statistics"""
    print("\n" + "=" * 70)
    print("EXAMPLE 13: Vulnerability Scanner Statistics")
    print("=" * 70)

    sqli = PayloadDatabase.get_sql_injection_payloads()
    xss = PayloadDatabase.get_xss_payloads()
    ssrf = PayloadDatabase.get_ssrf_payloads()
    code_inj = PayloadDatabase.get_code_injection_payloads()
    nosql = PayloadDatabase.get_nosql_injection_payloads()
    dir_trav = PayloadDatabase.get_directory_traversal_payloads()
    waf = PayloadDatabase.get_waf_bypass_payloads()
    creds = PayloadDatabase.get_default_credentials()

    stats = {
        "SQL Injection": sum(len(v) for v in sqli.values()),
        "XSS": sum(len(v) for v in xss.values()),
        "SSRF": sum(len(v) for v in ssrf.values()),
        "Code Injection": sum(len(v) for v in code_inj.values()),
        "NoSQL Injection": sum(len(v) for v in nosql.values()),
        "Directory Traversal": sum(len(v) for v in dir_trav.values()),
        "WAF Bypass": sum(len(v) for v in waf.values()),
        "Default Credentials": sum(len(v) for v in creds.values()),
    }

    print("\n[+] Payload Statistics:")
    for vuln_type, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
        print(f"    {vuln_type:.<30} {count:>3} payloads")

    total = sum(stats.values())
    print(f"\n    {'TOTAL':.<30} {total:>3} payloads")


def main():
    """Run all examples"""
    print("\n" + "=" * 70)
    print("ADVANCED VULNERABILITY SCANNER - COMPREHENSIVE EXAMPLES")
    print("=" * 70)

    print("\nRunning all examples...\n")

    try:
        example_1_basic_sql_injection_test()
    except:
        print("[!] Example 1 requires network access")

    try:
        example_2_xss_detection_forms()
    except:
        print("[!] Example 2 requires network access")

    try:
        example_3_technology_detection()
    except:
        print("[!] Example 3 requires network access")

    try:
        example_4_ssrf_detection()
    except:
        print("[!] Example 4 skipped")

    example_5_payload_database_access()
    example_6_default_credentials()
    example_7_code_injection_payloads()
    example_8_nosql_injection()
    example_9_waf_bypass()
    example_10_multiple_targets()
    example_11_programmatic_scanning()
    example_12_get_vs_post()
    example_13_payload_statistics()

    print("\n" + "=" * 70)
    print("All examples completed!")
    print("=" * 70)
    print("\nFor interactive scanning, run: python vuln_scanner.py")


if __name__ == "__main__":
    main()
