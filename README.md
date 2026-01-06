# Monero Brain Wallet Generator

> This repository contains a Python implementation demonstrating how a **Monero** brain wallet can be derived from a passphrase using Argon2id.

## Requirements

> Python 3.8+

### Python dependencies

`
pip install argon2-cffi pynacl pycryptodome
`

## Install

`
pip install -r requirements.txt
`

## Usage

### Basic interactive mode

`
python3 monero-brain-wallet.py
`

### Show help

`
python3 monero-brain-wallet.py -h
`

### Provide passphrase directly (non-interactive)

`
python3 monero-brain-wallet.py -p "my-memorable-long-and-unique-password"
`

### Use a custom salt

> Using a custom salt is strongly recommended. Choose a unique and memorable value, such as your email address (or your email combined with extra text).

`
python3 monero-brain-wallet.py -s "your-email@example.com"
`

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
When using a custom salt, both the password and the salt must be saved for recovery.

**Do NOT use brain wallets with basic keys to store real funds.**
Brain wallets are unsafe and have historically resulted in permanent loss of funds.

## When and why this can be useful (good news)
Despite their risks, Monero brain wallets have some properties that make them less fragile than Bitcoin-style brain wallets, especially for educational, experimental, or constrained use cases.

## Why Cracking Monero brainwallets are harder than from Bitcoin
- No address-based balance lookup
- Unlike Bitcoin, an attacker cannot simply check whether a guessed Monero address has funds.
- They must:
  - Scan blocks
  - Derive outputs
  - Perform cryptographic checks for every guessed wallet.
  -
- Wallet scanning is expensive
  - Each guessed keypair requires scanning many blocks to detect owned outputs, which significantly increases the cost of large-scale brute-force attacks.
  - No global UTXO visibility
- Monero’s privacy design prevents attackers from quickly filtering “interesting” wallets.

These properties do not make brain wallets safe but they do make mass automated attacks more costly than in transparent chains like Bitcoin.

## Cryptography Algorithm

This project deliberately uses Argon2id instead of fast hash functions like SHA-256.

Advantages:

- Memory-hard by design
- Each hash requires a configurable amount of RAM and time, not just CPU.
- Expensive to parallelize GPUs and ASICs gain far less advantage compared to SHA-256.

Using Argon2id significantly increases the economic cost of password cracking, even though it cannot make weak passphrases safe.

## Reasonable use cases
This project may be appropriate for:
- Cryptography education
- Fast wallet generation
- Demonstrating Monero key derivation
- Low-value, experimental wallets
- Cold, offline thought experiments
- Research into wallet recovery mechanisms

It is not appropriate for:
- Storing meaningful funds
- Long-term savings
- Users who may forget credentials
- Any scenario requiring official wallet recovery
