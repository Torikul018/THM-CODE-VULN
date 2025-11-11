# Password Generator Tool

A comprehensive Python-based password generator with strength analysis and multiple generation options.

## Features

✓ **Generate Secure Passwords** - Create random passwords with customizable length and character types  
✓ **Multiple Generation** - Generate multiple passwords at once  
✓ **Strength Analysis** - Check password strength with detailed breakdown  
✓ **Custom Options** - Include/exclude uppercase, lowercase, digits, and special characters  
✓ **Interactive CLI** - User-friendly command-line interface  

## Installation

No external dependencies required! Uses only Python standard library.

```bash
# Python 3.6+ required
python password_generator.py
```

## Usage

### Interactive Mode

Run the script and follow the menu:

```bash
python password_generator.py
```

Menu options:
- **1**: Generate a single password with default or custom length
- **2**: Generate multiple passwords at once
- **3**: Check the strength of an existing password
- **4**: Custom generation with specific character types
- **5**: Exit

### Programmatic Usage

```python
from password_generator import PasswordGenerator

# Initialize the generator
gen = PasswordGenerator()

# Generate a simple password (12 characters by default)
password = gen.generate()
print(password)  # Example: "aB3$xY9#Lm2K"

# Generate with custom length
password = gen.generate(length=16)

# Generate without special characters
password = gen.generate(
    length=14,
    use_uppercase=True,
    use_lowercase=True,
    use_digits=True,
    use_special=False
)

# Generate multiple passwords
passwords = gen.generate_multiple(count=10, length=12)

# Check password strength
strength, details = gen.check_strength("MyP@ssw0rd123")
print(f"Strength: {strength}")
print(f"Details: {details}")
```

## Password Strength Levels

The strength checker rates passwords on a 6-point scale:

| Level | Score | Criteria |
|-------|-------|----------|
| Very Weak | 0-1 | Minimal character diversity or short length |
| Weak | 1-2 | Limited character types |
| Fair | 2-3 | Basic diversity but could be stronger |
| Good | 3-4 | Decent security with most character types |
| Very Good | 4-5 | Strong with all character types |
| Excellent | 5-6 | Maximum security: 12+ chars + all types |

## Examples

### Generate a 16-character password with all character types:
```python
pwd = gen.generate(length=16)
```

### Generate passwords without numbers:
```python
pwd = gen.generate(use_digits=False)
```

### Check 5 passwords and find the strongest:
```python
passwords = gen.generate_multiple(count=5)
strengths = [gen.check_strength(p)[0] for p in passwords]
for pwd, strength in zip(passwords, strengths):
    print(f"{pwd}: {strength}")
```

## API Reference

### `PasswordGenerator.generate()`

Generate a single password.

**Parameters:**
- `length` (int): Password length, minimum 4. Default: 12
- `use_uppercase` (bool): Include uppercase letters. Default: True
- `use_lowercase` (bool): Include lowercase letters. Default: True
- `use_digits` (bool): Include digits (0-9). Default: True
- `use_special` (bool): Include special characters (!@#$, etc.). Default: True

**Returns:** str - The generated password

**Raises:** ValueError if length < 4 or no character types selected

### `PasswordGenerator.generate_multiple()`

Generate multiple passwords at once.

**Parameters:**
- `count` (int): Number of passwords to generate. Default: 5
- `**kwargs`: All parameters from `generate()` method

**Returns:** list - List of generated passwords

### `PasswordGenerator.check_strength()`

Analyze password strength.

**Parameters:**
- `password` (str): The password to analyze

**Returns:** tuple
- First element: str - Strength level
- Second element: dict - Details with keys:
  - `length` (int): Password length
  - `has_uppercase` (bool): Contains uppercase letters
  - `has_lowercase` (bool): Contains lowercase letters
  - `has_digits` (bool): Contains digits
  - `has_special` (bool): Contains special characters

## Security Notes

- Generated passwords use Python's `random` module which is cryptographically secure for password generation
- Passwords are randomized with character shuffling to avoid predictable patterns
- All character types are guaranteed at least 1 occurrence when enabled
- No passwords are stored or logged

## File Structure

```
password_generator.py    - Main password generator class and CLI
README.md               - This file
example_usage.py        - Example usage script
```

## License

Free to use for personal and commercial purposes.

## Changelog

### v1.0 (Initial Release)
- Password generation with customizable options
- Strength analysis and rating
- Interactive CLI menu
- Batch generation support
