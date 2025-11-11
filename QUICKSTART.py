#!/usr/bin/env python3
"""
QUICK START GUIDE - Password Generator Tool
Copy and paste these commands into your terminal to get started
"""

# ============================================================================
# QUICK START
# ============================================================================

# 1. RUN INTERACTIVE MODE (User-friendly menu):
#    python password_generator.py

# 2. RUN EXAMPLES:
#    python example_usage.py

# 3. USE IN YOUR PYTHON CODE:

from password_generator import PasswordGenerator

gen = PasswordGenerator()

# Generate a password
pwd = gen.generate()
print(f"Your password: {pwd}")

# Check its strength
strength, details = gen.check_strength(pwd)
print(f"Strength: {strength}")

# ============================================================================
# COMMON USE CASES
# ============================================================================

# For a website account:
web_pwd = gen.generate(length=14, use_special=True)

# For API/database (very secure):
api_pwd = gen.generate(length=32)

# For simple PIN (no special chars):
pin = gen.generate(length=8, use_special=False)

# For 10 different passwords:
batch = gen.generate_multiple(count=10, length=12)
for i, pwd in enumerate(batch, 1):
    print(f"{i}. {pwd}")

# For passwords without vowels (sometimes required):
# (Note: this example removes vowels from generated password)
pwd = gen.generate(length=12)
pwd_no_vowels = ''.join(c for c in pwd if c.lower() not in 'aeiou')

# ============================================================================
# FEATURES
# ============================================================================

# CUSTOMIZE CHARACTER TYPES:
#   use_uppercase=True/False    - Include A-Z
#   use_lowercase=True/False    - Include a-z
#   use_digits=True/False       - Include 0-9
#   use_special=True/False      - Include !@#$%^&*() etc.

# GENERATE MULTIPLE:
#   gen.generate_multiple(count=5, length=16)

# CHECK STRENGTH:
#   strength, details = gen.check_strength("MyP@ss123")
#   Strength levels: Very Weak, Weak, Fair, Good, Very Good, Excellent

# ============================================================================
# EXAMPLES BY USE CASE
# ============================================================================

# Social Media (simple, 12-16 chars, no special)
social = gen.generate(length=14, use_special=False)
print(f"Social Media: {social}")

# Banking/Email (very strong)
banking = gen.generate(length=20)
print(f"Banking: {banking}")

# WiFi/Network (alphanumeric, often 12-32 chars)
wifi = gen.generate(length=20, use_special=False)
print(f"WiFi: {wifi}")

# API Keys (very long, all characters)
api_key = gen.generate(length=40)
print(f"API Key: {api_key}")

# Database Password (strong, readable mix)
db_pwd = gen.generate(length=16)
print(f"Database: {db_pwd}")

# ============================================================================
# COMMAND LINE USAGE
# ============================================================================

# Run the tool interactively:
#   $ python password_generator.py
#   
#   Then choose:
#   1 - Generate a single password
#   2 - Generate multiple passwords
#   3 - Check password strength
#   4 - Custom settings
#   5 - Exit

# ============================================================================
# NOTES
# ============================================================================

# - No external dependencies needed (uses only Python standard library)
# - Works with Python 3.6 and above
# - Passwords are truly random (cryptographically secure)
# - Guaranteed to include at least one of each enabled character type
# - No passwords are saved or logged

print("\nPassword Generator Tool is ready to use!")
print("Run: python password_generator.py")
