import WebSocket from 'ws';
import crypto, { X509Certificate } from "crypto";
import * as encryption from './encryption.js'
import * as messaging from './messaging.js'

const CA_URL = "ws://localhost:8090";

export class Client {
    constructor(name, serverUrl, destinationNode, peerServer) {
        this.name = name;
        this.serverUrl = serverUrl;
        this.destination = destinationNode;
        this.isConnectionSecure = false;
        this.peerServer = peerServer;

        this.handshakePromise = new Promise((resolve, reject) => {
            this._resolveHandshake = resolve;
            this._rejectHandshake = reject;
        });

        this.connect()
    }

    connect() {
        this.ws = new WebSocket(this.serverUrl);

        this.ws.on('open', async () => {
            console.log(`[${this.name}] Connected to server`);
            await this.sendHello();

            messaging.getFullMessage(this.ws, async (message, destination, source, type) => {
                if (destination === "BCAST"){
                    const decrypted = this.handleProtectedMessage(message, source);
                    await this.peerServer.sendBroadcastMessage(decrypted, this);
                    return;
                }
                switch (type) {
                    // receive server HELLO message
                    case 2:
                        console.log(`[${this.name}] Received message from server`);
                        await this.handleServerHelloResponse(message);
                        break;
                    // receive READY message
                    case 4:
                        this.handleFinishMessage(message);
                        await this.sendReadyMessage();
                        this._resolveHandshake();
                        break;
                    // receive protected message
                    case 5:
                        this.handleProtectedMessage(message);
                        break;
                }
            });
         });

        this.ws.on('error', (error) =>
            console.error(`[${this.name}] WebSocket error:`, error.message));

        this.ws.on('close', () =>
            console.log(`[${this.name}] Connection closed`));
    }

    async sendHello() {
        try {
            this.clientNonce = crypto.randomBytes(32);
            const message = JSON.stringify({nonce: this.clientNonce.toString('base64')});
            console.log(`[${this.name}] Send hello to server`);
            await messaging.sendMessageInParts(this.ws, message, this.destination, 1, this.name);
        } catch (error) {
            console.error(`[${this.name}] Error sending hello message:`, error.message);
            this.ws.close();
        }
    }

    async handleServerHelloResponse(message) {
        try {
            const messageObj = JSON.parse(message);
            this.serverNonce = Buffer.from(messageObj.nonce, 'base64');
            const cert = messageObj.certificate;

            if (!messageObj.certificate)
                throw new Error('Certificate is missing in server response');

            const isValid = await this.verifyCertificate(cert);

            if (isValid) {
                this.extractPublicKey(messageObj.certificate);
                await this.sendSecret();
                this.generateSessionKey();
            } else {
                this.ws.close();
            }
        } catch (error) {
            console.error(`[${this.name}] Error processing server response:`, error.message);
            this.ws.close();
            this._rejectHandshake(error);
        }
    }

    verifyCertificate(certificate) {
        return new Promise((resolve, reject) => {
            const wsCA = new WebSocket(CA_URL);

            console.log(`[${this.name}] Try to connect to CA server`);
            wsCA.on("open", () => {
                console.log(`[${this.name}] Connected to CA server`);
                wsCA.send(JSON.stringify({certificate: certificate}));
                console.log(`[${this.name}] Sent cert to CA for verification`);

                wsCA.on("message", (message) => {
                    try {
                        const response = JSON.parse(message);
                        if (response.isValid) {
                            console.log(`[${this.name}] Certificate verified successfully`);
                            resolve(true);
                        } else {
                            console.error(`[${this.name}] Certificate verification failed`);
                            console.error(`[${this.name}] CA message:`, response.message);
                            resolve(false);
                        }
                    } catch (error) {
                        console.error(`[${this.name}] Error parsing CA response:`, error.message);
                        resolve(false);
                    } finally {
                        wsCA.close();
                    }
                })
            })

            wsCA.on('error', (error) => {
                console.error(`[${this.name}] CA connection error:`, error.message);
                reject(error);
                this._rejectHandshake(error);
            });

            wsCA.on('close', () =>
                console.log(`[${this.name}] CA connection closed`));
        });
    }

    extractPublicKey(certificate) {
        try {
            const x509 = new X509Certificate(certificate);
            this.serverPublicKey = x509.publicKey.export({
                type: 'spki',
                format: 'pem'
            });
            console.log(`[${this.name}] Extracted server public key`);
        } catch (error) {
            console.error(`[${this.name}] Error extracting public key:`, error.message);
            this._rejectHandshake(error);
            throw error;
        }
    }

    async sendSecret() {
        try {
            if (!this.serverPublicKey)
                throw new Error('Server public key is not available');

            this.premaster = crypto.randomBytes(48);
            const encryptedPremaster = crypto.publicEncrypt(
                {
                    key: this.serverPublicKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
                },
                this.premaster
            );

            const message = JSON.stringify({secret: encryptedPremaster.toString("base64")});


            console.log(`[${this.name}] Send encrypted premaster to server`);
            await messaging.sendMessageInParts(this.ws, message, this.destination,3, this.name);
        } catch (error) {
            console.error(`[${this.name}] Error sending secret:`, error.message);
            this.ws.close();
            this._rejectHandshake(error);
        }
    }

    generateSessionKey() {
        try {
            this.sessionKey = encryption.generateSessionKey(
                this.premaster,
                this.clientNonce,
                this.serverNonce)
            console.error(`[${this.name}] Session key was successfully generated.`);
        } catch (error) {
            console.error(`[${this.name}] Error while generating session key:`, error.message);
            this._rejectHandshake(error);
        }
    }

    async sendReadyMessage() {
        try {
            const message = "READY";
            const encryptedMessage = encryption.encryptMessage(this.sessionKey, message)

            console.log(`[${this.name}] Send encrypted \"READY\" message to server`);
            await messaging.sendMessageInParts(this.ws, encryptedMessage, this.destination,4, this.name);
        } catch (error) {
            console.error(`[${this.name}] Error sending encrypted \"READY\" message to server.`, error.message);
            this.ws.close();
            this._rejectHandshake(error);
        }
    }

    handleFinishMessage(message) {
        try {
            const decryptedMessage = encryption.decryptMessage(this.sessionKey, message);

            this.isConnectionSecure = decryptedMessage.toString() === "READY";
            if(!this.isConnectionSecure)
                throw new Error("\"READY\" message was not recognised")

            console.log(`[${this.name}] Received \"READY\" message from server`);
        } catch (error) {
            console.error(`[${this.name}] Error while handling server \"READY\" message:`, error.message);
            this.ws.close();
            this._rejectHandshake(error);
        }
    }

    handleProtectedMessage(message) {
        try {
            const decryptedMessage = encryption.decryptMessage(this.sessionKey, message).toString();
            console.log(`[${this.name}] Received \"${decryptedMessage}\" message from server`);
            return decryptedMessage;
        } catch (error) {
            console.error(`[${this.name}] Error handling protected message:`, error.message);
        }
    }

    async sendMessageToServer(message) {
        try {
            if (!this.isConnectionSecure)
                throw new Error(`Connection to server ${this.destination} is unsecure`);

            const encryptedMessage = encryption.encryptMessage(this.sessionKey, message)
            console.log(`[${this.name}] Send encrypted message to server`);
            await messaging.sendMessageInParts(this.ws, encryptedMessage, this.destination, 5, this.name);

        } catch (error) {
            console.error(`[${this.name}] Error sending message to server:`, error.message);
        }
    }

    async sendBroadcastMessage(message) {
        try {
            if (!this.isConnectionSecure)
                throw new Error(`Connection to server ${this.destination} is unsecure`);

            const encryptedMessage = encryption.encryptMessage(this.sessionKey, message);
            console.log(`[${this.name}] Send Broadcast message`);
            await messaging.sendMessageInParts(this.ws, encryptedMessage, "BCAST", 0, this.name);

        } catch (error) {
            console.error(`[${this.name}] Broadcast failed:`, error.message);
        }
    }
}
