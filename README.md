

# Monero Brain Wallet Generator

This repository demonstrates how a **Monero brain wallet** can be constructed using
a passphrase, a memory-hard key derivation function (Argon2id), and Monero’s
cryptographic rules.

## Requirements

Python 3.8+

### Python dependencies

`pip install argon2-cffi pynacl pycryptodome`

Install with:

`pip install -r requirements.txt`

## Usage

### Basic interactive mode

`python3 monero-brain-wallet.py`

### Show help

`python3 monero-brain-wallet.py -h`


### Provide passphrase directly (non-interactive)

`python3 monero-brain-wallet.py -p "your passphrase here"`

### Use a custom salt

`python3 monero-brain-wallet.py -s "your-custom-salt"`

Default salt:

> monero-brain-wallet


## What this project does

This script:

- Derives a Monero wallet deterministically from a passphrase
- Uses **Argon2id** (memory-hard) to slow brute-force attacks
- Correctly reduces entropy to a valid **Ed25519 scalar**
- Derives:
  - Private spend key
  - Private view key
  - Public spend key
  - Public view key
  - Mainnet address
- Supports command-line options for password and salt

This is **NOT an official Monero wallet** and is **NOT compatible with standard wallet recovery methods**.

---

## Why brain wallets are dangerous

Even with Argon2:

- Humans choose weak or guessable phrases
- Attackers can run large-scale offline cracking
- No checksum or recovery protection
- No official Monero support
- Forgotten passphrase = permanent loss

> **If it can be remembered easily, it can probably be cracked.**

---
## ⚠️ WARNINGS ⚠️

If you select a custom salt, be sure to save both your password and the salt, as both are required for recovery.

**Do NOT use brain wallets with basic keys to store real funds.**
Brain wallets are unsafe and have historically resulted in permanent loss of funds.
