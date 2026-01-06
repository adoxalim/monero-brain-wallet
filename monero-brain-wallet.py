#!/usr/bin/env python3

import argparse
import getpass
from argon2.low_level import hash_secret_raw, Type
from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
from Crypto.Hash import keccak

# ---- Monero constants ----

L = int(
    "723700557733226221397318656304299424085711635937990760600195093828545425857",
    10
)

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DEFAULT_SALT = b"monero-brain-wallet"
MIN_SALT_LEN = 12
ENCODED_BLOCK_SIZES = {
    1: 2,
    2: 3,
    3: 5,
    4: 6,
    5: 7,
    6: 9,
    7: 10,
    8: 11,
}

# ---- Crypto utilities ----

def keccak_256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def sc_reduce32(data: bytes) -> bytes:
    i = int.from_bytes(data, "little") % L
    return i.to_bytes(32, "little")

def hash_to_scalar(data: bytes) -> bytes:
    return sc_reduce32(keccak_256(data))

def encode_block(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = ALPHABET[rem] + out
    return out

def monero_base58_encode(data: bytes) -> str:
    result = ""
    i = 0
    while i < len(data):
        block = data[i:i+8]
        enc = encode_block(block)
        enc = enc.rjust(
            ENCODED_BLOCK_SIZES[len(block)],
            ALPHABET[0]
        )
        result += enc
        i += 8
    return result

def is_valid_monero_address(address: str) -> bool:
    if len(address) != 95:
        return False
    if not address.startswith("4"):
        return False
    for c in address:
        if c not in ALPHABET:
            return False
    return True

# ---- Brain wallet derivation ----

def brain_wallet(passphrase: str, salt: bytes):
    seed = hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=256 * 1024,  # 256 MB
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )

    spend_key = sc_reduce32(seed)
    view_key = hash_to_scalar(spend_key)

    pub_spend = crypto_scalarmult_ed25519_base_noclamp(spend_key)
    pub_view  = crypto_scalarmult_ed25519_base_noclamp(view_key)

    network_byte = b"\x12"  # mainnet
    data = network_byte + pub_spend + pub_view
    checksum = keccak_256(data)[:4]
    address = monero_base58_encode(data + checksum)
    
    if not is_valid_monero_address(address):
        raise ValueError("Generated wallet is INVALID (address check failed)")

    return {
        "private_spend_key": spend_key.hex(),
        "private_view_key": view_key.hex(),
        "public_spend_key": pub_spend.hex(),
        "public_view_key": pub_view.hex(),
        "address": address
    }

# ---- Argument parsing ----

def parse_args():
    parser = argparse.ArgumentParser(
        description="Monero Brain Wallet Generator (EDUCATIONAL USE ONLY)",
        epilog=(
            "Examples:\n"
            "  python3 xmr-brain-wallet.py\n"
            "  python3 xmr-brain-wallet.py -p \"hello\"\n"
            "  python3 xmr-brain-wallet.py -p \"hello\" -s \"customsalthere\"\n"
            "  python3 xmr-brain-wallet.py -s \"customsalthere\"\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-p", "--password",
        help="Brain wallet passphrase (if omitted, you will be prompted)"
    )

    parser.add_argument(
        "-s", "--salt",
        help="Custom salt (minimum 12 characters)"
    )

    return parser.parse_args()

# ---- Main ----

def main():
    args = parse_args()

    # Password handling
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Enter brain wallet passphrase: ")

    # Salt handling
    if args.salt:
        salt = args.salt
        while len(salt) < MIN_SALT_LEN:
            print(f"Salt must be at least {MIN_SALT_LEN} characters.")
            salt = input("Enter a longer salt: ")
        salt_bytes = salt.encode()
    else:
        salt_bytes = DEFAULT_SALT

    try:
        wallet = brain_wallet(password, salt_bytes)
    except Exception as e:
        print("\nERROR:", e)
        print("No wallet generated.")
        raise SystemExit(1)


    print("\n=== Monero Brain Wallet ===")
    print(f"Salt: {salt_bytes.decode(errors='ignore')}\n")
    for k, v in wallet.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    main()

