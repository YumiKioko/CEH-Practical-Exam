# Password Pattern Analysis Guide

## Pattern Syntax Reference

### Basic Placeholders
| Symbol | Meaning | Examples |
|--------|---------|----------|
| `A` | Uppercase letter | A-Z |
| `a` | Lowercase letter | a-z |
| `d` | Digit | 0-9 |
| `s` | Special character | !@#$%^&*() |
| `*` | Any character | Wildcard |
| `?` | Optional character | May or may not appear |

## Common Pattern Formats

### Similar to `Aaaa*aaa*A*`

#### Corporate Password Patterns
```
Aaaa*aaa*A*    = Capital, 3 lowercase, any chars, 3 lowercase, capital, any chars
Aaaa*d*        = Capital, 3 lowercase, any, digit (Password1)
Aaaa*sA*       = Capital, 3 lowercase, special, capital (Pass@Word)
Aaaa*d*s       = Capital, 3 lowercase, digit, special (Pass1!)
```

#### Complex Security Policies
```
A*a*d*s        = Capital, any, lowercase, digit, special (P@ssw0rd!)
Aaaa*d*sA*     = Capital, 3 lowercase, digit, special, capital (Pass1!W)
A*a*a*d*s*a    = Mixed case with digit and special in middle
Aaaa*d*sA*d    = 12+ chars with multiple requirements
```

## Tool-Specific Pattern Syntax

### Hashcat Mask Attack
```bash
# Hashcat placeholders
?u = Uppercase letter
?l = Lowercase letter  
?d = Digit
?s = Special character
?a = Any character

# Pattern conversions:
Aaaa*d*s    = ?u?l?l?l?d?s
Aaaa*aaa*A* = ?u?l?l?l?a?a?a?u?a
A*a*d*s*a*  = ?u?a?l?d?s?l?a
```

### John the Ripper Mask Attack
```bash
# John placeholders
?u = Uppercase
?l = Lowercase
?d = Digit
?s = Special

# Pattern examples:
john --mask='?u?l?l?l?d?l?l?l' hashes.txt
john --mask='?u?l?l?l?a?a?a?u?a' hashes.txt
```

## Pattern Generation Commands

### Using Crunch
```bash
# Basic pattern: Aaaa*d (Capital, 3 lowercase, digit)
crunch 8 8 -t Aaaa%d -o pattern_passwords.txt

# Complex pattern: Aaaa*d*s (Capital, 3 lowercase, digit, special)
crunch 8 8 -t Aaaa%d%s -o complex_passwords.txt

# Mixed case with special: A*a*d*s
crunch 8 8 -t A%a%d%s -o mixed_pattern.txt
```

### Using RSMangler
```bash
# Generate patterns from base words
echo "password" | rsmangler --file - --pattern "Aaaa*d*s"
echo "company" | rsmangler --file - --pattern "Aaaa*2024"
```

### Custom Python Pattern Generator
```python
#!/usr/bin/env python3
import itertools
import string

def generate_from_pattern(pattern):
    char_sets = {
        'A': string.ascii_uppercase,
        'a': string.ascii_lowercase,
        'd': string.digits,
        's': '!@#$%^&*',
        '*': string.ascii_letters + string.digits + '!@#$%^&*'
    }
    
    combinations = [char_sets[char] for char in pattern]
    
    for combo in itertools.product(*combinations):
        yield ''.join(combo)

# Usage
pattern = "Aaaa*d"
for pwd in generate_from_pattern(pattern):
    print(pwd)
```

## Real-World Pattern Examples

### Corporate Password Policies
| Policy | Pattern | Example |
|--------|---------|---------|
| 8 chars, upper, lower, digit | `Aaaaaaad` | `Password1` |
| 8 chars, upper, lower, digit, special | `Aaaaaaads` | `Password1!` |
| 12 chars, mixed case, 2 digits | `A*a*a*d*d*a*a*a*a*a` | `P@ssw0rd123` |
| Capital first, special required | `Aaaa*s*a*a` | `Pass@word` |

### Seasonal/Temporal Patterns
```
Aaaa*2024*     = Spring2024!, Summer2024@
Aaaa*Q1*       = WinterQ1!, SpringQ2@
Aaaa*Jan*      = PasswordJan!, UserJanuary@
```

## Pattern Analysis Tools

### Analyze Existing Passwords
```bash
# Convert passwords to patterns and count frequency
awk '{
    pattern = $1
    gsub(/[A-Z]/, "A", pattern)
    gsub(/[a-z]/, "a", pattern) 
    gsub(/[0-9]/, "d", pattern)
    gsub(/[^A-Za-z0-9]/, "s", pattern)
    print pattern
}' password_list.txt | sort | uniq -c | sort -rn
```

### Advanced Pattern Analysis Script
```python
#!/usr/bin/env python3
import collections
import re

def analyze_password_patterns(filename):
    patterns = collections.Counter()
    
    with open(filename, 'r', errors='ignore') as f:
        for line in f:
            password = line.strip()
            if password:
                # Convert to pattern notation
                pattern = re.sub(r'[A-Z]', 'A', password)
                pattern = re.sub(r'[a-z]', 'a', pattern)
                pattern = re.sub(r'[0-9]', 'd', pattern)
                pattern = re.sub(r'[^A-Za-z0-9]', 's', pattern)
                
                patterns[pattern] += 1
    
    # Display top patterns
    for pattern, count in patterns.most_common(20):
        print(f"{count:6d} {pattern}")

analyze_password_patterns('passwords.txt')
```

## Attack Commands with Patterns

### Hashcat Mask Attacks
```bash
# Basic corporate pattern: Aaaa*d (8 chars)
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?l?l?d

# Complex pattern: Aaaa*d*s (8 chars)
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?l?l?d?s

# Custom length with pattern
hashcat -m 1000 hashes.txt -a 3 -i ?u?l?l?l?d?a?a?a
```

### John the Ripper Mask Attacks
```bash
# Standard pattern attack
john --mask='?u?l?l?l?d?l?l?l' hashes.txt

# Incremental pattern
john --mask='?u?l?l?l?d?a' --min-length=8 --max-length=12 hashes.txt
```

## Password Policy to Pattern Mapping

### Common Organizational Policies
| Policy Description | Pattern | Example |
|-------------------|---------|---------|
| Minimum 8 chars, 1 uppercase, 1 lowercase, 1 digit | `Aaaaaaad*` | `Welcome1` |
| 8 chars, 1 upper, 1 lower, 1 digit, 1 special | `Aaaaaaads` | `Welcome1!` |
| 12 chars, mixed case, 2 digits, 1 special | `A*a*a*d*d*s*a*a*a*a*` | `P@ssw0rd123!` |
| Capital first letter, no consecutive repeats | `A*a*a*a*a*a*a*` | `Password` |

## Quick Reference Cheat Sheet

### Pattern Conversions
| Human Readable | Hashcat | John | Meaning |
|---------------|---------|------|---------|
| `Aaaa` | `?u?l?l?l` | `?u?l?l?l` | Capital + 3 lowercase |
| `Aaaa*d` | `?u?l?l?l?l?l?l?d` | `?u?l?l?l?l?l?l?d` | 8 chars with digit |
| `A*a*d*s` | `?u?a?l?d?s` | `?u?a?l?d?s` | Mixed complexity |
| `Aaaa*2024` | `?u?l?l?l?d?d?d?d` | `?u?l?l?l?d?d?d?d` | Seasonal pattern |

### Common Attack Patterns
```bash
# Top 10 most effective patterns for corporate environments:
1. Aaaaaaad      # Basic 8-char with digit
2. Aaaa*d*s      # 8-char with digit and special  
3. Aaaa*aaa      # Simple word based
4. A*a*d*s*a     # Mixed complexity
5. Aaaa*2024     # Year-based
6. Aaaa*Q1       # Quarter-based
7. Aaaa*!        # Simple special append
8. Aaaa*123      # Common digit append
9. A*a*a*d*d     # Two digits somewhere
10. Aaaa*s*d     # Special before digit
```

## Best Practices

### Pattern Selection
- Start with most common organizational patterns
- Focus on minimum length requirements first
- Include seasonal and temporal patterns
- Consider company-specific conventions

### Performance Optimization
```bash
# Use incremental attacks for variable lengths
hashcat -m 1000 hashes.txt -a 3 -i ?u?l?l?l?d?a?a

# Combine with wordlists for hybrid attacks
hashcat -m 1000 hashes.txt -a 6 wordlist.txt ?d?s
```

---

**Pro Tip**: Always analyze existing password breaches from similar organizations to identify the most common patterns for your target! 🎯