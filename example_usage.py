"""
Example usage of the Password Generator Tool
Demonstrates all major features and use cases
"""

from password_generator import PasswordGenerator


def main():
    """Demonstrate all features of the password generator."""
    gen = PasswordGenerator()

    print("\n" + "=" * 70)
    print("PASSWORD GENERATOR - EXAMPLE USAGE")
    print("=" * 70)

    # Example 1: Simple password generation
    print("\n[EXAMPLE 1] Generate a simple 12-character password")
    print("-" * 70)
    pwd1 = gen.generate()
    print(f"Password: {pwd1}")
    strength, details = gen.check_strength(pwd1)
    print(f"Strength: {strength}")
    print(f"Details: Length={details['length']}, "
          f"Upper={details['has_uppercase']}, "
          f"Lower={details['has_lowercase']}, "
          f"Digit={details['has_digits']}, "
          f"Special={details['has_special']}")

    # Example 2: Custom length password
    print("\n[EXAMPLE 2] Generate a 20-character password")
    print("-" * 70)
    pwd2 = gen.generate(length=20)
    print(f"Password: {pwd2}")
    strength, _ = gen.check_strength(pwd2)
    print(f"Strength: {strength}")

    # Example 3: Password without special characters
    print("\n[EXAMPLE 3] Generate password without special characters (alphanumeric only)")
    print("-" * 70)
    pwd3 = gen.generate(length=16, use_special=False)
    print(f"Password: {pwd3}")
    strength, details = gen.check_strength(pwd3)
    print(f"Strength: {strength}")
    print(f"Has Special: {details['has_special']}")

    # Example 4: Password with only uppercase and digits
    print("\n[EXAMPLE 4] Generate with uppercase and digits only")
    print("-" * 70)
    pwd4 = gen.generate(length=12, use_lowercase=False, use_special=False)
    print(f"Password: {pwd4}")
    strength, details = gen.check_strength(pwd4)
    print(f"Strength: {strength}")
    print(f"Has Lowercase: {details['has_lowercase']}")

    # Example 5: Generate multiple passwords
    print("\n[EXAMPLE 5] Generate 5 different passwords for different accounts")
    print("-" * 70)
    passwords = gen.generate_multiple(count=5, length=14)
    for i, pwd in enumerate(passwords, 1):
        strength, _ = gen.check_strength(pwd)
        print(f"  {i}. {pwd} [{strength}]")

    # Example 6: Strength analysis of different passwords
    print("\n[EXAMPLE 6] Analyze strength of various passwords")
    print("-" * 70)
    test_passwords = [
        "password",
        "Password1",
        "Password1!",
        "MySecureP@ss123!",
        "aB3$xY9#Lm2KqWe7"
    ]
    
    for pwd in test_passwords:
        strength, details = gen.check_strength(pwd)
        rating = "[WEAK]" if strength in ["Very Weak", "Weak"] else "[GOOD]"
        print(f"  {pwd:20} -> {strength:12} {rating}")
        print(f"    Length: {details['length']:2} | "
              f"Upper: {str(details['has_uppercase']):5} | "
              f"Lower: {str(details['has_lowercase']):5} | "
              f"Digit: {str(details['has_digits']):5} | "
              f"Special: {str(details['has_special']):5}")

    # Example 7: Generate passwords for specific use cases
    print("\n[EXAMPLE 7] Passwords for specific use cases")
    print("-" * 70)
    
    print("  Social Media (simple, no special chars):")
    social_pwd = gen.generate(length=12, use_special=False)
    print(f"    {social_pwd}")
    
    print("  Bank Account (maximum security):")
    bank_pwd = gen.generate(length=20)
    print(f"    {bank_pwd}")
    
    print("  API Key (long, with special chars):")
    api_pwd = gen.generate(length=32)
    print(f"    {api_pwd}")
    
    print("  WiFi Password (alphanumeric only):")
    wifi_pwd = gen.generate(length=16, use_special=False)
    print(f"    {wifi_pwd}")

    # Example 8: Batch generation with strength filter
    print("\n[EXAMPLE 8] Generate 10 passwords and filter for 'Good' or better")
    print("-" * 70)
    batch = gen.generate_multiple(count=10, length=14)
    good_passwords = []
    
    for pwd in batch:
        strength, _ = gen.check_strength(pwd)
        if strength in ["Good", "Very Good", "Excellent"]:
            good_passwords.append((pwd, strength))
    
    print(f"Generated 10, found {len(good_passwords)} with 'Good' or better strength:")
    for pwd, strength in good_passwords:
        print(f"  {pwd} [{strength}]")

    print("\n" + "=" * 70)
    print("End of examples. Run 'python password_generator.py' for interactive mode.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
