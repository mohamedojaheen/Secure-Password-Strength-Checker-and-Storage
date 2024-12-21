# Secure-Password-Strength-Checker-and-Storage
## Overview

- This tool **_analyzes_** your password to check it's **_strength_** and check its hash in **_a list of famous cracked hashes_**.
- It also can **_generate_** passwords for you and automatically **_copy them to your clipboard_**.
- It also **_stores_** your password hashed in **``SHA1``** and encrypted in **``AES``** and retrieves it using a **_master_** password.
- You can also use it to check **_how old_** are your stored passwords.

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
