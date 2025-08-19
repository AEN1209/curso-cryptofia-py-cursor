#!/usr/bin/env node

const { Command } = require('commander');
const CryptoLib = require('./crypto_lib');
const fs = require('fs');

const program = new Command();
const cryptoLib = new CryptoLib();

program
    .name('cryptocli')
    .description('A command-line cryptographic tool')
    .version('1.0.0');

// SHA256 Command
program.command('sha256')
    .description('Compute SHA256 hash of a string or file')
    .option('-s, --string <value>', 'String to hash')
    .option('-f, --file <path>', 'File to hash')
    .action(async (options) => {
        if (options.string) {
            console.log(`SHA256 (string): ${cryptoLib.sha256String(options.string)}`);
        } else if (options.file) {
            try {
                const hash = await cryptoLib.sha256File(options.file);
                console.log(`SHA256 (file): ${hash}`);
            } catch (error) {
                console.error(`Error hashing file: ${error.message}`);
            }
        } else {
            console.error('Error: Please provide either a string (--string) or a file (--file).');
        }
    });

// Keccak256 Command
program.command('keccak256')
    .description('Compute Keccak256 hash of a string or file')
    .option('-s, --string <value>', 'String to hash')
    .option('-f, --file <path>', 'File to hash')
    .action(async (options) => {
        if (options.string) {
            console.log(`Keccak256 (string): ${cryptoLib.keccak256String(options.string)}`);
        } else if (options.file) {
            try {
                const hash = await cryptoLib.keccak256File(options.file);
                console.log(`Keccak256 (file): ${hash}`);
            } catch (error) {
                console.error(`Error hashing file: ${error.message}`);
            }
        } else {
            console.error('Error: Please provide either a string (--string) or a file (--file).');
        }
    });

// AES Command
program.command('aes')
    .description('Perform AES encryption or decryption')
    .option('-e, --encrypt', 'Encrypt data')
    .option('-d, --decrypt', 'Decrypt data')
    .option('--data <value>', 'Data (string or file path) to encrypt/decrypt', '')
    .option('--key <value>', 'AES key (16, 24, or 32 bytes)', '')
    .option('--iv <value>', 'Initialization Vector (hex string) for decryption', '')
    .option('--encrypted-data <value>', 'Encrypted data (hex string) for decryption', '')
    .option('-o, --output-file <path>', 'Output file for encrypted/decrypted data')
    .action((options) => {
        if (options.encrypt) {
            const result = cryptoLib.aesEncrypt(options.data, options.key);
            if (result) {
                if (options.outputFile) {
                    fs.writeFileSync(options.outputFile, `${result.iv}:${result.encryptedData}`);
                    console.log(`Encrypted data saved to ${options.outputFile}`);
                } else {
                    console.log(`IV (hex): ${result.iv}`);
                    console.log(`Encrypted Data (hex): ${result.encryptedData}`);
                }
            }
        } else if (options.decrypt) {
            const decrypted = cryptoLib.aesDecrypt(options.iv, options.encryptedData, options.key);
            if (decrypted) {
                if (options.outputFile) {
                    fs.writeFileSync(options.outputFile, decrypted);
                    console.log(`Decrypted data saved to ${options.outputFile}`);
                } else {
                    console.log(`Decrypted Data: ${decrypted}`);
                }
            }
        } else {
            console.error('Error: Please specify either --encrypt or --decrypt.');
        }
    });

// RSA Command
program.command('rsa')
    .description('Perform RSA operations')
    .option('-g, --generate-keys', 'Generate RSA keys')
    .option('-e, --encrypt', 'Encrypt data')
    .option('-d, --decrypt', 'Decrypt data')
    .option('--bits <value>', 'Key size in bits (default: 2048)', parseInt)
    .option('--private-output <path>', 'Output file for private key')
    .option('--public-output <path>', 'Output file for public key')
    .option('--public-key-file <path>', 'File containing RSA public key')
    .option('--private-key-file <path>', 'File containing RSA private key')
    .option('--message <value>', 'Message to encrypt/sign')
    .option('--ciphertext <value>', 'Ciphertext (hex string) to decrypt/verify')
    .action((options) => {
        if (options.generateKeys) {
            const { privateKey, publicKey } = cryptoLib.rsaGenerateKeys(options.bits);
            fs.writeFileSync(options.privateOutput, privateKey);
            fs.writeFileSync(options.publicOutput, publicKey);
            console.log(`RSA keys generated: Private key saved to ${options.privateOutput}, Public key saved to ${options.publicOutput}`);
        } else if (options.encrypt) {
            const publicKey = fs.readFileSync(options.publicKeyFile, 'utf8');
            const encrypted = cryptoLib.rsaEncrypt(publicKey, options.message);
            console.log(`Encrypted message (hex): ${encrypted}`);
        } else if (options.decrypt) {
            const privateKey = fs.readFileSync(options.privateKeyFile, 'utf8');
            const decrypted = cryptoLib.rsaDecrypt(privateKey, options.ciphertext);
            console.log(`Decrypted message: ${decrypted}`);
        } else {
            console.error('Error: Please specify an RSA operation (--generate-keys, --encrypt, or --decrypt).');
        }
    });

// secp256k1 Command
program.command('secp256k1')
    .description('Perform secp256k1 operations')
    .option('-g, --generate-keys', 'Generate secp256k1 keys')
    .option('-s, --sign', 'Sign data')
    .option('-v, --verify', 'Verify signature')
    .option('-e, --eth-address', 'Get Ethereum address')
    .option('--private-output <path>', 'Output file for private key')
    .option('--public-output <path>', 'Output file for public key')
    .option('--private-key-file <path>', 'File containing secp256k1 private key')
    .option('--public-key-file <path>', 'File containing secp256k1 public key')
    .option('--message <value>', 'Message to sign/verify')
    .option('--signature <value>', 'Signature (hex string) to verify')
    .action((options) => {
        if (options.generateKeys) {
            const { privateKey, publicKey } = cryptoLib.secp256k1GenerateKeys();
            fs.writeFileSync(options.privateOutput, privateKey);
            fs.writeFileSync(options.publicOutput, publicKey);
            console.log(`secp256k1 keys generated: Private key saved to ${options.privateOutput}, Public key saved to ${options.publicOutput}`);
        } else if (options.sign) {
            const privateKey = fs.readFileSync(options.privateKeyFile, 'utf8');
            const signature = cryptoLib.secp256k1Sign(privateKey, options.message);
            console.log(`Signature (hex): ${signature}`);
        } else if (options.verify) {
            const publicKey = fs.readFileSync(options.publicKeyFile, 'utf8');
            const isValid = cryptoLib.secp256k1Verify(publicKey, options.message, options.signature);
            console.log(`Signature valid: ${isValid}`);
        } else if (options.ethAddress) {
            const publicKey = fs.readFileSync(options.publicKeyFile, 'utf8');
            const address = cryptoLib.secp256k1GetEthereumAddress(publicKey);
            console.log(`Ethereum address: ${address}`);
        } else {
            console.error('Error: Please specify a secp256k1 operation.');
        }
    });

// secp256r1 Command
program.command('secp256r1')
    .description('Perform secp256r1 operations')
    .option('-g, --generate-keys', 'Generate secp256r1 keys')
    .option('-s, --sign', 'Sign data')
    .option('-v, --verify', 'Verify signature')
    .option('--private-output <path>', 'Output file for private key')
    .option('--public-output <path>', 'Output file for public key')
    .option('--private-key-file <path>', 'File containing secp256r1 private key')
    .option('--public-key-file <path>', 'File containing secp256r1 public key')
    .option('--message <value>', 'Message to sign/verify')
    .option('--signature <value>', 'Signature (hex string) to verify')
    .action((options) => {
        if (options.generateKeys) {
            const { privateKey, publicKey } = cryptoLib.secp256r1GenerateKeys();
            fs.writeFileSync(options.privateOutput, privateKey);
            fs.writeFileSync(options.publicOutput, publicKey);
            console.log(`secp256r1 keys generated: Private key saved to ${options.privateOutput}, Public key saved to ${options.publicOutput}`);
        } else if (options.sign) {
            const privateKey = fs.readFileSync(options.privateKeyFile, 'utf8');
            const signature = cryptoLib.secp256r1Sign(privateKey, options.message);
            console.log(`Signature (hex): ${signature}`);
        } else if (options.verify) {
            const publicKey = fs.readFileSync(options.publicKeyFile, 'utf8');
            const isValid = cryptoLib.secp256r1Verify(publicKey, options.message, options.signature);
            console.log(`Signature valid: ${isValid}`);
        } else {
            console.error('Error: Please specify a secp256r1 operation.');
        }
    });

program.parse(process.argv);
