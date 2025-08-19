import hashlib
import sys
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256 as PyCryptodomeSHA256
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.curves import NIST256p
from ecdsa.util import sigencode_string, sigdecode_string
# from sha3 import keccak_256

class CryptoLib:
    def __init__(self):
        pass

    def sha256_string(self, text):
        """Computes SHA256 hash of a string."""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def sha256_file(self, filepath):
        """Computes SHA256 hash of a file."""
        if not os.path.exists(filepath):
            return None
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def keccak256_string(self, text):
        """Computes Keccak256 hash of a string."""
        return hashlib.sha3_256(text.encode('utf-8')).hexdigest()

    def keccak256_file(self, filepath):
        """Computes Keccak256 hash of a file."""
        if not os.path.exists(filepath):
            return None
        hasher = hashlib.sha3_256()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def aes_encrypt(self, data, key):
        """Encrypts data using AES."""
        try:
            if os.path.exists(data) and isinstance(data, str):
                with open(data, 'rb') as f:
                    data_bytes = f.read()
            elif isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                return None, "Invalid data source. Must be string or existing file path."

            key_bytes = key.encode('utf-8') if isinstance(key, str) else key
            if len(key_bytes) not in [16, 24, 32]:
                return None, "AES key must be 16, 24, or 32 bytes long."

            cipher = AES.new(key_bytes, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
            return cipher.nonce + ciphertext + tag, None
        except Exception as e:
            return None, str(e)

    def aes_decrypt(self, encrypted_data, key):
        """Decrypts data using AES."""
        try:
            key_bytes = key.encode('utf-8') if isinstance(key, str) else key
            if len(key_bytes) not in [16, 24, 32]:
                return None, "AES key must be 16, 24, or 32 bytes long."

            nonce = encrypted_data[:16]
            ciphertext = encrypted_data[16:-16]
            tag = encrypted_data[-16:]

            cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_data.decode('utf-8'), None
        except Exception as e:
            return None, str(e)

    def rsa_generate_keys(self, bits=2048):
        """Generates RSA public and private keys."""
        key = RSA.generate(bits)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return private_key, public_key

    def rsa_encrypt(self, public_key, message):
        """Encrypts a message using RSA public key."""
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(message.encode('utf-8')).hex()

    def rsa_decrypt(self, private_key, ciphertext):
        """Decrypts a ciphertext using RSA private key."""
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(bytes.fromhex(ciphertext)).decode('utf-8')

    def secp256k1_generate_keys(self):
        """Generates secp256k1 private and public keys."""
        sk = SigningKey.generate(curve=SECP256k1)
        private_key = sk.to_string().hex()
        public_key = sk.get_verifying_key().to_string().hex()
        return private_key, public_key

    def secp256k1_sign(self, private_key_hex, message):
        """Signs a message using secp256k1 private key."""
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        message_hash = PyCryptodomeSHA256.new(message.encode('utf-8'))
        signature = sk.sign(message_hash.digest(), sigencode=sigencode_string)
        return signature.hex()

    def secp256k1_verify(self, public_key_hex, message, signature_hex):
        """Verifies a signature using secp256k1 public key."""
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
        message_hash = PyCryptodomeSHA256.new(message.encode('utf-8'))
        signature = bytes.fromhex(signature_hex)
        try:
            return vk.verify(signature, message_hash.digest(), sigdecode=sigdecode_string)
        except:
            return False

    def secp256k1_get_ethereum_address(self, public_key_hex):
        """Computes Ethereum address from secp256k1 public key."""
        public_key_bytes = bytes.fromhex(public_key_hex)
        if len(public_key_bytes) == 65:  # Uncompressed public key
            public_key_bytes = public_key_bytes[1:] # Remove prefix 0x04
        keccak_hash = hashlib.sha3_256(public_key_bytes).hexdigest()
        address = '0x' + keccak_hash[-40:]
        return address

    def secp256r1_generate_keys(self):
        """Generates secp256r1 private and public keys."""
        sk = SigningKey.generate(curve=NIST256p)
        private_key = sk.to_string().hex()
        public_key = sk.get_verifying_key().to_string().hex()
        return private_key, public_key

    def secp256r1_sign(self, private_key_hex, message):
        """Signs a message using secp256r1 private key."""
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=NIST256p)
        message_hash = PyCryptodomeSHA256.new(message.encode('utf-8'))
        signature = sk.sign(message_hash.digest(), sigencode=sigencode_string)
        return signature.hex()

    def secp256r1_verify(self, public_key_hex, message, signature_hex):
        """Verifies a signature using secp256r1 public key."""
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=NIST256p)
        message_hash = PyCryptodomeSHA256.new(message.encode('utf-8'))
        signature = bytes.fromhex(signature_hex)
        try:
            return vk.verify(signature, message_hash.digest(), sigdecode=sigdecode_string)
        except:
            return False

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cryptographic Library CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # SHA256
    sha256_parser = subparsers.add_parser("sha256", help="SHA256 operations")
    sha256_parser.add_argument("--string", type=str, help="String to hash")
    sha256_parser.add_argument("--file", type=str, help="File to hash")

    # Keccak256
    keccak256_parser = subparsers.add_parser("keccak256", help="Keccak256 operations")
    keccak256_parser.add_argument("--string", type=str, help="String to hash")
    keccak256_parser.add_argument("--file", type=str, help="File to hash")

    # AES
    aes_parser = subparsers.add_parser("aes", help="AES operations")
    aes_subparsers = aes_parser.add_subparsers(dest="aes_command", help="AES commands")

    aes_encrypt_parser = aes_subparsers.add_parser("encrypt", help="Encrypt data with AES")
    aes_encrypt_parser.add_argument("--data", type=str, required=True, help="String or file path to encrypt")
    aes_encrypt_parser.add_argument("--key", type=str, required=True, help="AES key")
    aes_encrypt_parser.add_argument("--output-file", type=str, help="Output file for encrypted data")

    aes_decrypt_parser = aes_subparsers.add_parser("decrypt", help="Decrypt data with AES")
    aes_decrypt_parser.add_argument("--data", type=str, required=True, help="Hexadecimal string of encrypted data or file path")
    aes_decrypt_parser.add_argument("--key", type=str, required=True, help="AES key")
    aes_decrypt_parser.add_argument("--output-file", type=str, help="Output file for decrypted data")

    # RSA
    rsa_parser = subparsers.add_parser("rsa", help="RSA operations")
    rsa_subparsers = rsa_parser.add_subparsers(dest="rsa_command", help="RSA commands")

    rsa_gen_parser = rsa_subparsers.add_parser("generate-keys", help="Generate RSA keys")
    rsa_gen_parser.add_argument("--bits", type=int, default=2048, help="Key size in bits (default: 2048)")
    rsa_gen_parser.add_argument("--private-output", type=str, required=True, help="Output file for private key")
    rsa_gen_parser.add_argument("--public-output", type=str, required=True, help="Output file for public key")

    rsa_encrypt_parser = rsa_subparsers.add_parser("encrypt", help="Encrypt data with RSA")
    rsa_encrypt_parser.add_argument("--public-key-file", type=str, required=True, help="File containing RSA public key")
    rsa_encrypt_parser.add_argument("--message", type=str, required=True, help="Message to encrypt")

    rsa_decrypt_parser = rsa_subparsers.add_parser("decrypt", help="Decrypt data with RSA")
    rsa_decrypt_parser.add_argument("--private-key-file", type=str, required=True, help="File containing RSA private key")
    rsa_decrypt_parser.add_argument("--ciphertext", type=str, required=True, help="Ciphertext to decrypt (hex string)")

    # secp256k1
    secp256k1_parser = subparsers.add_parser("secp256k1", help="secp256k1 operations")
    secp256k1_subparsers = secp256k1_parser.add_subparsers(dest="secp256k1_command", help="secp256k1 commands")

    secp256k1_gen_parser = secp256k1_subparsers.add_parser("generate-keys", help="Generate secp256k1 keys")
    secp256k1_gen_parser.add_argument("--private-output", type=str, required=True, help="Output file for private key")
    secp256k1_gen_parser.add_argument("--public-output", type=str, required=True, help="Output file for public key")

    secp256k1_sign_parser = secp256k1_subparsers.add_parser("sign", help="Sign data with secp256k1")
    secp256k1_sign_parser.add_argument("--private-key-file", type=str, required=True, help="File containing secp256k1 private key")
    secp256k1_sign_parser.add_argument("--message", type=str, required=True, help="Message to sign")

    secp256k1_verify_parser = secp256k1_subparsers.add_parser("verify", help="Verify secp256k1 signature")
    secp256k1_verify_parser.add_argument("--public-key-file", type=str, required=True, help="File containing secp256k1 public key")
    secp256k1_verify_parser.add_argument("--message", type=str, required=True, help="Original message")
    secp256k1_verify_parser.add_argument("--signature", type=str, required=True, help="Signature to verify (hex string)")

    secp256k1_eth_address_parser = secp256k1_subparsers.add_parser("eth-address", help="Get Ethereum address from secp256k1 public key")
    secp256k1_eth_address_parser.add_argument("--public-key-file", type=str, required=True, help="File containing secp256k1 public key")

    # secp256r1
    secp256r1_parser = subparsers.add_parser("secp256r1", help="secp256r1 operations")
    secp256r1_subparsers = secp256r1_parser.add_subparsers(dest="secp256r1_command", help="secp256r1 commands")

    secp256r1_gen_parser = secp256r1_subparsers.add_parser("generate-keys", help="Generate secp256r1 keys")
    secp256r1_gen_parser.add_argument("--private-output", type=str, required=True, help="Output file for private key")
    secp256r1_gen_parser.add_argument("--public-output", type=str, required=True, help="Output file for public key")

    secp256r1_sign_parser = secp256r1_subparsers.add_parser("sign", help="Sign data with secp256r1")
    secp256r1_sign_parser.add_argument("--private-key-file", type=str, required=True, help="File containing secp256r1 private key")
    secp256r1_sign_parser.add_argument("--message", type=str, required=True, help="Message to sign")

    secp256r1_verify_parser = secp256r1_subparsers.add_parser("verify", help="Verify secp256r1 signature")
    secp256r1_verify_parser.add_argument("--public-key-file", type=str, required=True, help="File containing secp256r1 public key")
    secp256r1_verify_parser.add_argument("--message", type=str, required=True, help="Original message")
    secp256r1_verify_parser.add_argument("--signature", type=str, required=True, help="Signature to verify (hex string)")

    args = parser.parse_args()
    crypto_lib = CryptoLib()

    if args.command == "sha256":
        if args.string:
            print(f"SHA256 (string): {crypto_lib.sha256_string(args.string)}")
        elif args.file:
            result = crypto_lib.sha256_file(args.file)
            if result:
                print(f"SHA256 (file): {result}")
            else:
                print(f"Error: File not found or could not be read: {args.file}")
    elif args.command == "keccak256":
        if args.string:
            print(f"Keccak256 (string): {crypto_lib.keccak256_string(args.string)}")
        elif args.file:
            result = crypto_lib.keccak256_file(args.file)
            if result:
                print(f"Keccak256 (file): {result}")
            else:
                print(f"Error: File not found or could not be read: {args.file}")
    elif args.command == "aes":
        if args.aes_command == "encrypt":
            encrypted_data, error = crypto_lib.aes_encrypt(args.data, args.key)
            if encrypted_data:
                if args.output_file:
                    with open(args.output_file, 'wb') as f:
                        f.write(encrypted_data)
                    print(f"Encrypted data saved to {args.output_file}")
                else:
                    print(f"Encrypted data (hex): {encrypted_data.hex()}")
            else:
                print(f"Error: {error}")
        elif args.aes_command == "decrypt":
            try:
                # If the data is from a file, read it as bytes
                if os.path.exists(args.data):
                    with open(args.data, 'rb') as f:
                        data_to_decrypt = f.read()
                else:
                    # Otherwise, assume it's a hex string
                    data_to_decrypt = bytes.fromhex(args.data)

                decrypted_data, error = crypto_lib.aes_decrypt(data_to_decrypt, args.key)
                if decrypted_data:
                    if args.output_file:
                        with open(args.output_file, 'w') as f:
                            f.write(decrypted_data)
                        print(f"Decrypted data saved to {args.output_file}")
                        print(f"DEBUG: Decrypted data before writing to file: {decrypted_data}")
                    else:
                        print(f"Decrypted data: {decrypted_data}")
                else:
                    print(f"Error: {error}")
            except ValueError:
                print("Error: Invalid hexadecimal string for decryption.")

    elif args.command == "rsa":
        if args.rsa_command == "generate-keys":
            private_key, public_key = crypto_lib.rsa_generate_keys(args.bits)
            with open(args.private_output, 'w') as f:
                f.write(private_key)
            with open(args.public_output, 'w') as f:
                f.write(public_key)
            print(f"RSA keys generated: Private key saved to {args.private_output}, Public key saved to {args.public_output}")
        elif args.rsa_command == "encrypt":
            with open(args.public_key_file, 'r') as f:
                public_key = f.read()
            encrypted_message = crypto_lib.rsa_encrypt(public_key, args.message)
            print(f"Encrypted message (hex): {encrypted_message}")
        elif args.rsa_command == "decrypt":
            with open(args.private_key_file, 'r') as f:
                private_key = f.read()
            decrypted_message = crypto_lib.rsa_decrypt(private_key, args.ciphertext)
            print(f"Decrypted message: {decrypted_message}")

    elif args.command == "secp256k1":
        if args.secp256k1_command == "generate-keys":
            private_key, public_key = crypto_lib.secp256k1_generate_keys()
            with open(args.private_output, 'w') as f:
                f.write(private_key)
            with open(args.public_output, 'w') as f:
                f.write(public_key)
            print(f"secp256k1 keys generated: Private key saved to {args.private_output}, Public key saved to {args.public_output}")
        elif args.secp256k1_command == "sign":
            with open(args.private_key_file, 'r') as f:
                private_key = f.read()
            signature = crypto_lib.secp256k1_sign(private_key, args.message)
            print(f"Signature (hex): {signature}")
        elif args.secp256k1_command == "verify":
            with open(args.public_key_file, 'r') as f:
                public_key = f.read()
            is_valid = crypto_lib.secp256k1_verify(public_key, args.message, args.signature)
            print(f"Signature valid: {is_valid}")
        elif args.secp256k1_command == "eth-address":
            with open(args.public_key_file, 'r') as f:
                public_key = f.read()
            address = crypto_lib.secp256k1_get_ethereum_address(public_key)
            print(f"Ethereum address: {address}")

    elif args.command == "secp256r1":
        if args.secp256r1_command == "generate-keys":
            private_key, public_key = crypto_lib.secp256r1_generate_keys()
            with open(args.private_output, 'w') as f:
                f.write(private_key)
            with open(args.public_output, 'w') as f:
                f.write(public_key)
            print(f"secp256r1 keys generated: Private key saved to {args.private_output}, Public key saved to {args.public_output}")
        elif args.secp256r1_command == "sign":
            with open(args.private_key_file, 'r') as f:
                private_key = f.read()
            signature = crypto_lib.secp256r1_sign(private_key, args.message)
            print(f"Signature (hex): {signature}")
        elif args.secp256r1_command == "verify":
            with open(args.public_key_file, 'r') as f:
                public_key = f.read()
            is_valid = crypto_lib.secp256r1_verify(public_key, args.message, args.signature)
            print(f"Signature valid: {is_valid}")
