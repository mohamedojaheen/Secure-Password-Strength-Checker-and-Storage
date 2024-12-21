# Secure-Password-Strength-Checker-and-Storage
## Overview

This tool provides a secure, command-line interface for password generation, analysis, and storage. It evaluates password strength based on entropy, length, complexity, and common vulnerabilities. Passwords can be securely stored using **``AES`` encryption** and **``SHA1`` hash** with a **master password** and a **timeout** mechanism to **prevent brute force attacks** against you master password.

## Features

**1. Password Analysis :**

  - Checks for length, complexity, common patterns, and inclusion in breached password lists.
  - Calculates an entropy score to quantify password strength.
  - Provides actionable recommendations for weak passwords.


**2. Password Generation :**

  - Generates strong random passwords.
  - Automatically copies generated passwords to the clipboard.


**3. Password Storage :**

  - Stores passwords securely using **``AES``** encryption and **``SHA1``** hash.
  - Requires a master password for encryption/decryption.


**4. Password Retrieval :**

  - Retrieves stored passwords with their ages.


**5. Password Aging :**

  - Alerts when stored passwords exceed a predefined age limit (default: 90 days).

**6. Timeout :**

  - After 3 wrong attempts for entering the msater password you will be timedout (default: 60 seconds).



## Commands

**1. ``new``**
  - Combines password generation, analysis, and optional storage.
  - Flow :
    1. Ask if the user wants to generate a new password.
    2. If generating :
      - Generate a strong random password.
      - Display and copy it to the clipboard.
      - Prompt to store the password.
    3. If not generating :
      - Accept a user-provided password.
      - Analyze the password for strength and display recommendations.
      - Ask "Are you sure?" for weak passwords.
      - Prompt to store the password.

**2. ``analyze``**
  - Analyzes a provided password.
  - Displays:
    - Length, complexity, and pattern checks.
    - Breach status.
    - Entropy score.
    - Recommendations for improvement.

**3. ``retrieve``**
  - Retrieves stored passwords.
  - Displays:
    - Decrypted passwords.
    - Age of each password in days.

**4. ``check-age``**
  - Checks the age of stored passwords.
  - Alerts if any password is older than the predefined maximum age (default: 90 days).


## Password Strength Criteria

**Length :**
  - Minimum 12 characters.

**Complexity :**
  - Mix of uppercase, lowercase, numbers, and special characters.

**Common Patterns :**
  - Avoid predictable sequences like "123456" or "password".

**Entropy :**
  - Higher entropy indicates better resilience against brute-force attacks.
  - Entropy < 50 is considered weak.


## Storage Security

**1. Encryption :**
  - Passwords are encrypted using **``AES``** with a master password.
  - The master password is hashed with **``SHA1``** to generate the encryption key.

**2. Prevention against brute force attacks :**
  - After **3** wrong attempts at entering the master password for the previously stored passwords, a timeout will trigger that prevents you from entering the master password (default duration: 60 seconds).  

**3. Data File :**
  - Stored in passwords.json.
  - Includes :
    - Encrypted passwords.
    - Timestamps for password age tracking.
    - The lockout time if the master password was entered wrong more than 3 times.

## Installation

1. Clone the repositry :
```bash
git clone https://github.com/mohamedojaheen/Secure-Password-Strength-Checker-and-Storage.git
cd Password_Analyzer
```

2. Install dependencies :
```bash
pip install requirements.txt
```

## Usage

- For help command use **``-help``** :
```bash
python cli.py -help
```

- To check you password's strength use **``analyze``** :
```bash
python cli.py analyze
```

- To add or generate a new password use **``new``** :
```bash
python cli.py new
```

- To retrieve your password use **``retrieve``** :
```bash
python cli.py retrieve
```

- To check how old are your passwords use **``check-age``** :
```bash
python cli.py check-age
```


> [!CAUTION]
> This code is provided as is. Use it at your own risk.
