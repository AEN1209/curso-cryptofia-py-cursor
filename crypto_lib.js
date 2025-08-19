const crypto = require('crypto');
const { keccak256 } = require('js-sha3');
const NodeRSA = require('node-rsa');
const { secp256k1, secp256r1 } = require('@noble/curves/secp256k1'); // Using secp256k1 from noble-curves
const { bytesToHex, hexToBytes } = require('@ethereumjs/util');
const fs = require('fs');

class CryptoLib {
    sha256String(text) {
        return crypto.createHash('sha256').update(text).digest('hex');
    }

    sha256File(filepath) {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(filepath);
            stream.on('data', chunk => hash.update(chunk));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', err => reject(err));
        });
    }

    keccak256String(text) {
        return keccak256(text);
    }

    keccak256File(filepath) {
        return new Promise((resolve, reject) => {
            fs.readFile(filepath, (err, data) => {
                if (err) {
                    return reject(err);
                }
                resolve(keccak256(data));
            });
        });
    }

    aesEncrypt(data, key) {
        try {
            const keyBuffer = Buffer.from(key, 'utf8');
            if (![16, 24, 32].includes(keyBuffer.length)) {
                throw new Error("AES key must be 16, 24, or 32 bytes long.");
            }
            
            let dataBuffer;
            if (fs.existsSync(data)) {
                dataBuffer = fs.readFileSync(data);
            } else {
                dataBuffer = Buffer.from(data, 'utf8');
            }

            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);
            let encrypted = cipher.update(dataBuffer);
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
        } catch (error) {
            console.error("AES Encryption Error:", error.message);
            return null;
        }
    }

    aesDecrypt(ivHex, encryptedDataHex, key) {
        try {
            const keyBuffer = Buffer.from(key, 'utf8');
            if (![16, 24, 32].includes(keyBuffer.length)) {
                throw new Error("AES key must be 16, 24, or 32 bytes long.");
            }

            const iv = Buffer.from(ivHex, 'hex');
            const encryptedText = Buffer.from(encryptedDataHex, 'hex');
            const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, iv);
            let decrypted = decipher.update(encryptedText);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            return decrypted.toString('utf8');
        } catch (error) {
            console.error("AES Decryption Error:", error.message);
            return null;
        }
    }

    rsaGenerateKeys(bits = 2048) {
        const key = new NodeRSA({ b: bits });
        const privateKey = key.exportKey('pkcs1-private-pem');
        const publicKey = key.exportKey('pkcs1-public-pem');
        return { privateKey, publicKey };
    }

    rsaEncrypt(publicKey, message) {
        try {
            const key = new NodeRSA();
            key.importKey(publicKey, 'pkcs1-public-pem');
            return key.encrypt(message, 'hex');
        } catch (error) {
            console.error("RSA Encryption Error:", error.message);
            return null;
        }
    }

    rsaDecrypt(privateKey, ciphertext) {
        try {
            const key = new NodeRSA();
            key.importKey(privateKey, 'pkcs1-private-pem');
            return key.decrypt(ciphertext, 'utf8');
        } catch (error) {
            console.error("RSA Decryption Error:", error.message);
            return null;
        }
    }

    secp256k1GenerateKeys() {
        const privKey = secp256k1.utils.randomPrivateKey();
        const pubKey = secp256k1.getPublicKey(privKey);
        return { privateKey: bytesToHex(privKey), publicKey: bytesToHex(pubKey) };
    }

    secp256k1Sign(privateKeyHex, message) {
        const privKey = hexToBytes(privateKeyHex);
        const msgHash = hexToBytes(crypto.createHash('sha256').update(message).digest('hex'));
        const signature = secp256k1.sign(msgHash, privKey);
        return bytesToHex(signature.toCompactRawBytes());
    }

    secp256k1Verify(publicKeyHex, message, signatureHex) {
        try {
            const pubKey = hexToBytes(publicKeyHex);
            const msgHash = hexToBytes(crypto.createHash('sha256').update(message).digest('hex'));
            const signature = hexToBytes(signatureHex);
            return secp256k1.verify(signature, msgHash, pubKey);
        } catch (error) {
            console.error("secp256k1 Verification Error:", error.message);
            return false;
        }
    }

    secp256k1GetEthereumAddress(publicKeyHex) {
        const pubKey = hexToBytes(publicKeyHex);
        // Remove 0x04 prefix for uncompressed public keys
        const pubKeyWithoutPrefix = pubKey.length === 65 ? pubKey.slice(1) : pubKey;
        const hash = keccak256(pubKeyWithoutPrefix);
        return '0x' + hash.substring(hash.length - 40);
    }

    secp256r1GenerateKeys() {
        const privKey = secp256r1.utils.randomPrivateKey();
        const pubKey = secp256r1.getPublicKey(privKey);
        return { privateKey: bytesToHex(privKey), publicKey: bytesToHex(pubKey) };
    }

    secp256r1Sign(privateKeyHex, message) {
        const privKey = hexToBytes(privateKeyHex);
        const msgHash = hexToBytes(crypto.createHash('sha256').update(message).digest('hex'));
        const signature = secp256r1.sign(msgHash, privKey);
        return bytesToHex(signature.toCompactRawBytes());
    }

    secp256r1Verify(publicKeyHex, message, signatureHex) {
        try {
            const pubKey = hexToBytes(publicKeyHex);
            const msgHash = hexToBytes(crypto.createHash('sha256').update(message).digest('hex'));
            const signature = hexToBytes(signatureHex);
            return secp256r1.verify(signature, msgHash, pubKey);
        } catch (error) {
            console.error("secp256r1 Verification Error:", error.message);
            return false;
        }
    }
}

module.exports = CryptoLib;
