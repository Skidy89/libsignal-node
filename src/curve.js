
'use strict';

const curveJs = require('curve25519-js');
const nodeCrypto = require('crypto');
// from: https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/lib/crypto.js
const PUBLIC_KEY_DER_PREFIX = Buffer.from([
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);
  
const PRIVATE_KEY_DER_PREFIX = Buffer.from([
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

function validatePrivKey(privKey) {
    if (!Buffer.isBuffer(privKey) || privKey.length !== 32) {
        throw new Error(`Invalid private key`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (!Buffer.isBuffer(pubKey)) {
        throw new Error(`Invalid public key type: ${pubKey?.constructor?.name || typeof pubKey}`);
    }
    if ((pubKey.length !== 33 || pubKey[0] !== 5) && pubKey.length !== 32) {
        throw new Error("Invalid public key");
    }
    if (pubKey.length === 33) {
        return pubKey.subarray(1);
    } else {
        console.warn("WARNING: Expected pubkey of length 33, please report the ST and client that generated it");
        return pubKey;
    }
}

exports.generateKeyPair = function() {
    if(typeof nodeCrypto.generateKeyPairSync === 'function') {
        const {publicKey: publicDerBytes, privateKey: privateDerBytes} = nodeCrypto.generateKeyPairSync(
            'x25519',
            {
                publicKeyEncoding: { format: 'der', type: 'spki' },
                privateKeyEncoding: { format: 'der', type: 'pkcs8' }
            }
        );
        // 33 bytes
        // first byte = 5 (version byte)
        const pubKey = publicDerBytes.subarray(PUBLIC_KEY_DER_PREFIX.length-1, PUBLIC_KEY_DER_PREFIX.length + 32);
        pubKey[0] = 5;
    
        const privKey = privateDerBytes.subarray(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);
    
        return {
            pubKey,
            privKey
        };
    } else {
        const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32));
        return {
            privKey: Buffer.isBuffer(keyPair.private) ? keyPair.private : Buffer.from(keyPair.private),
            pubKey: Buffer.isBuffer(keyPair.public) ? keyPair.public : Buffer.from(keyPair.public),
        };
    }
};

exports.calculateAgreement = function(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }

    if(typeof nodeCrypto.diffieHellman === 'function') {
        const nodePrivateKey = nodeCrypto.createPrivateKey({
            key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
            format: 'der',
            type: 'pkcs8'
        });
        const nodePublicKey = nodeCrypto.createPublicKey({
            key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
            format: 'der',
            type: 'spki'
        });
        
        return nodeCrypto.diffieHellman({
            privateKey: nodePrivateKey,
            publicKey: nodePublicKey,
        });
    } else {
        const secret = curveJs.sharedKey(privKey, pubKey);
        return Buffer.from(secret);
    }
};

exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    return Buffer.from(curveJs.sign(privKey, message));
};

exports.verifySignature = function(pubKey, msg, sig) {
    pubKey = scrubPubKeyFormat(pubKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    return curveJs.verify(pubKey, msg, sig);
};