import crypto from "crypto";

const BLOCK_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const ALGORITHM = 'aes-256-gcm';

export function encryptMessage(key, message) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(message);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    return Buffer.concat([iv, encrypted, authTag]);
}

export function decryptMessage(key, message) {
    const iv = message.subarray(0, IV_LENGTH);
    const payload = message.subarray(IV_LENGTH, message.length - AUTH_TAG_LENGTH);
    const authTag = message.subarray(message.length - AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    try {
        let decrypted = decipher.update(payload);
        return Buffer.concat([decrypted, decipher.final()]);
    } catch (err) {
        throw new Error(`Decryption failed! Integrity check failed or wrong key. ${err.message}.}`);
    }
}

export function generateSessionKey(secret, clientNonce, serverNonce) {
    const masterSeedData = Buffer.concat([clientNonce, serverNonce]);
    const sessionSeedData = Buffer.concat([serverNonce, clientNonce]);
    const masterLabel = "master secret";
    const sessionLabel = "session key";

    const masterSecret = PRF(secret, masterLabel, masterSeedData, BLOCK_LENGTH);
    return PRF(masterSecret, sessionLabel, sessionSeedData, BLOCK_LENGTH);
}

function PRF(secret, label, seedData, length){
    const labelBuffer = Buffer.from(label, 'ascii');
    const seed = Buffer.concat([labelBuffer, seedData]);
    return PSHA256(secret, seed, length);
}

function PSHA256(secret, seed, length) {
    let result= Buffer.alloc(0);
    let a = seed;

    while (result.length < length) {
        a = crypto.createHmac('sha256', secret).update(a).digest();

        const output = crypto
            .createHmac('sha256', secret)
            .update(Buffer.concat([a, seed]))
            .digest();

        result = Buffer.concat([result, output]);
    }

    return result.subarray(0, length);
}