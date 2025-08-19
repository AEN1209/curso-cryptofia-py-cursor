# CryptoLib - A Command-Line Cryptography Tool

CryptoLib is a Python-based command-line interface (CLI) tool that provides various cryptographic functionalities, including hashing (SHA256, Keccak256), symmetric encryption (AES), asymmetric encryption (RSA), and elliptic curve cryptography (secp256k1, secp256r1) with key generation, signing, and verification.

## Features

*   **SHA256 Hashing**: Hash strings or files.
*   **Keccak256 Hashing**: Hash strings or files (useful for Ethereum-related tasks).
*   **AES Encryption/Decryption**: Encrypt and decrypt data (strings or files) using a symmetric key.
*   **RSA Encryption/Decryption**: Generate RSA key pairs, encrypt messages with public keys, and decrypt with private keys.
*   **secp256k1 (Bitcoin/Ethereum Curve)**:
    *   Generate private and public keys.
    *   Sign messages.
    *   Verify signatures.
    *   Compute Ethereum addresses from public keys.
*   **secp256r1 (NIST P-256 Curve)**:
    *   Generate private and public keys.
    *   Sign messages.
    *   Verify signatures.

## Installation

1.  **Clone the repository**:

    ```bash
    git clone https://github.com/your-username/cryptolib.git
    cd cryptolib
    ```

2.  **Create a virtual environment (recommended)**:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: .\venv\Scripts\activate
    ```

3.  **Install dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

All commands are executed through `python crypto_lib.py <command> [options]`.

### SHA256 Hashing

*   **Hash a string**:

    ```bash
    python crypto_lib.py sha256 --string "Hello, World!"
    ```

*   **Hash a file**:

    ```bash
    python crypto_lib.py sha256 --file path/to/your/file.txt
    ```

### Keccak256 Hashing

*   **Hash a string**:

    ```bash
    python crypto_lib.py keccak256 --string "Hello, World!"
    ```

*   **Hash a file**:

    ```bash
    python crypto_lib.py keccak256 --file path/to/your/file.txt
    ```

### AES Encryption/Decryption

*   **Encrypt a string**:

    ```bash
    python crypto_lib.py aes encrypt --data "My secret message" --key "ThisIsASecretKey16"
    ```
    (The key must be 16, 24, or 32 bytes long).

*   **Encrypt a file**:

    ```bash
    python crypto_lib.py aes encrypt --data path/to/input.txt --key "ThisIsASecretKey16" --output-file encrypted.bin
    ```

*   **Decrypt a hexadecimal string**:

    ```bash
    python crypto_lib.py aes decrypt --data "<hexadecimal_encrypted_data>" --key "ThisIsASecretKey16"
    ```

*   **Decrypt an encrypted file**:

    ```bash
    python crypto_lib.py aes decrypt --data encrypted.bin --key "ThisIsASecretKey16" --output-file decrypted.txt
    ```

### RSA Encryption/Decryption

*   **Generate RSA keys**:

    ```bash
    python crypto_lib.py rsa generate-keys --private-output private_rsa.pem --public-output public_rsa.pem --bits 4096
    ```

*   **Encrypt a message**:

    ```bash
    python crypto_lib.py rsa encrypt --public-key-file public_rsa.pem --message "Confidential information"
    ```

*   **Decrypt a ciphertext**:

    ```bash
    python crypto_lib.py rsa decrypt --private-key-file private_rsa.pem --ciphertext "<hexadecimal_ciphertext>"
    ```

### secp256k1 Operations

*   **Generate secp256k1 keys**:

    ```bash
    python crypto_lib.py secp256k1 generate-keys --private-output private_k1.pem --public-output public_k1.pem
    ```

*   **Sign a message**:

    ```bash
    python crypto_lib.py secp256k1 sign --private-key-file private_k1.pem --message "My data to sign"
    ```

*   **Verify a signature**:

    ```bash
    python crypto_lib.py secp256k1 verify --public-key-file public_k1.pem --message "My data to sign" --signature "<hexadecimal_signature>"
    ```

*   **Get Ethereum address**:

    ```bash
    python crypto_lib.py secp256k1 eth-address --public-key-file public_k1.pem
    ```

### secp256r1 Operations

*   **Generate secp256r1 keys**:

    ```bash
    python crypto_lib.py secp256r1 generate-keys --private-output private_r1.pem --public-output public_r1.pem
    ```

*   **Sign a message**:

    ```bash
    python crypto_lib.py secp256r1 sign --private-key-file private_r1.pem --message "Another data to sign"
    ```

*   **Verify a signature**:

    ```bash
    python crypto_lib.py secp256r1 verify --public-key-file public_r1.pem --message "Another data to sign" --signature "<hexadecimal_signature>"
    ```

## Contributing

Feel free to fork the repository, open issues, and submit pull requests.

## License

This project is licensed under the MIT License.
