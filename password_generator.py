"""
Password Generator Tool
A comprehensive tool to generate secure passwords with customizable options.
"""

import random
import string
import sys
from typing import Tuple


class PasswordGenerator:
    """
    A class to generate secure passwords with various customization options.
    """

    def __init__(self):
        self.uppercase = string.ascii_uppercase
        self.lowercase = string.ascii_lowercase
        self.digits = string.digits
        self.special_chars = string.punctuation
        self.all_chars = self.uppercase + self.lowercase + self.digits + self.special_chars

    def generate(
        self,
        length: int = 12,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
    ) -> str:
        """
        Generate a password with specified criteria.

        Args:
            length: Length of the password (default 12)
            use_uppercase: Include uppercase letters (default True)
            use_lowercase: Include lowercase letters (default True)
            use_digits: Include digits (default True)
            use_special: Include special characters (default True)

        Returns:
            A randomly generated password string
        """
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")

        # Build character pool
        char_pool = ""
        if use_uppercase:
            char_pool += self.uppercase
        if use_lowercase:
            char_pool += self.lowercase
        if use_digits:
            char_pool += self.digits
        if use_special:
            char_pool += self.special_chars

        if not char_pool:
            raise ValueError("At least one character type must be selected")

        # Ensure at least one character from each selected type
        password_chars = []

        if use_uppercase:
            password_chars.append(random.choice(self.uppercase))
        if use_lowercase:
            password_chars.append(random.choice(self.lowercase))
        if use_digits:
            password_chars.append(random.choice(self.digits))
        if use_special:
            password_chars.append(random.choice(self.special_chars))

        # Fill remaining length with random characters from pool
        remaining_length = length - len(password_chars)
        password_chars.extend(random.choice(char_pool) for _ in range(remaining_length))

        # Shuffle to avoid predictable pattern
        random.shuffle(password_chars)

        return "".join(password_chars)

    def generate_multiple(self, count: int = 5, **kwargs) -> list:
        """
        Generate multiple passwords at once.

        Args:
            count: Number of passwords to generate (default 5)
            **kwargs: Additional arguments passed to generate()

        Returns:
            List of generated passwords
        """
        return [self.generate(**kwargs) for _ in range(count)]

    def check_strength(self, password: str) -> Tuple[str, dict]:
        """
        Analyze password strength.

        Args:
            password: Password to analyze

        Returns:
            Tuple of (strength_level, details_dict)
        """
        details = {
            "length": len(password),
            "has_uppercase": any(c.isupper() for c in password),
            "has_lowercase": any(c.islower() for c in password),
            "has_digits": any(c.isdigit() for c in password),
            "has_special": any(c in self.special_chars for c in password),
        }

        score = 0
        if details["length"] >= 8:
            score += 1
        if details["length"] >= 12:
            score += 1
        if details["has_uppercase"]:
            score += 1
        if details["has_lowercase"]:
            score += 1
        if details["has_digits"]:
            score += 1
        if details["has_special"]:
            score += 1

        strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Very Good", "Excellent"]
        strength = strength_levels[min(score, 5)]

        return strength, details


def main():
    """Main function for CLI usage."""
    generator = PasswordGenerator()

    print("\n" + "=" * 60)
    print("PASSWORD GENERATOR TOOL")
    print("=" * 60)

    while True:
        print("\n1. Generate Single Password")
        print("2. Generate Multiple Passwords")
        print("3. Check Password Strength")
        print("4. Custom Generation Settings")
        print("5. Exit")

        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == "1":
            try:
                length = int(input("Enter password length (default 12): ") or "12")
                password = generator.generate(length=length)
                print(f"\n[+] Generated Password: {password}")
                strength, _ = generator.check_strength(password)
                print(f"[+] Strength: {strength}")
            except ValueError as e:
                print(f"✗ Error: {e}")

        elif choice == "2":
            try:
                count = int(input("How many passwords? (default 5): ") or "5")
                length = int(input("Enter password length (default 12): ") or "12")
                passwords = generator.generate_multiple(count=count, length=length)
                print(f"\n[+] Generated {count} passwords:")
                for i, pwd in enumerate(passwords, 1):
                    print(f"  {i}. {pwd}")
            except ValueError as e:
                print(f"✗ Error: {e}")

        elif choice == "3":
            password = input("Enter password to check: ").strip()
            if not password:
                print("[-] Password cannot be empty")
                continue
            strength, details = generator.check_strength(password)
            print(f"\n[+] Password Strength: {strength}")
            print(f"  Length: {details['length']}")
            print(f"  Uppercase: {'YES' if details['has_uppercase'] else 'NO'}")
            print(f"  Lowercase: {'YES' if details['has_lowercase'] else 'NO'}")
            print(f"  Digits: {'YES' if details['has_digits'] else 'NO'}")
            print(f"  Special Characters: {'YES' if details['has_special'] else 'NO'}")

        elif choice == "4":
            print("\n--- Custom Generation Settings ---")
            try:
                length = int(input("Password length (default 12): ") or "12")
                use_upper = input("Include uppercase? (y/n, default y): ").lower() != "n"
                use_lower = input("Include lowercase? (y/n, default y): ").lower() != "n"
                use_digits = input("Include digits? (y/n, default y): ").lower() != "n"
                use_special = input("Include special chars? (y/n, default y): ").lower() != "n"

                password = generator.generate(
                    length=length,
                    use_uppercase=use_upper,
                    use_lowercase=use_lower,
                    use_digits=use_digits,
                    use_special=use_special,
                )
                print(f"\n[+] Generated Password: {password}")
                strength, _ = generator.check_strength(password)
                print(f"[+] Strength: {strength}")
            except ValueError as e:
                print(f"✗ Error: {e}")

        elif choice == "5":
            print("\n[+] Thank you for using Password Generator. Goodbye!")
            break

        else:
            print("[-] Invalid choice. Please enter 1-5.")


if __name__ == "__main__":
    main()
