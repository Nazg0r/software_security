import WebSocket, { WebSocketServer } from 'ws';
import crypto from "crypto";
import fs from 'fs';
import * as encryption from './encryption.js'
import * as messaging from './messaging.js'

export class Server {
    constructor(name, port) {
        this.name = name;
        this.port = port;
        this.privateKey = this.loadFile('Cert/server.key');
        this.certificate = this.loadFile('Cert/server.crt');
        this.ws = new WebSocketServer({port: this.port});
        this.connectionsCounter = 0;
        this.sessions = new Map();
        this.activeTunnels = new Map();
        this.connectedClients = new Map();
        this.routs = null;
        this.connections = null;
        this.isConnectionSecure = false;
        this.initialize();
    }

    loadFile(path) {
        try {
            return fs.readFileSync(path, 'utf8');
        } catch (error) {
            console.error(`[${this.name}] Error loading file ${path}:`, error.message);
            process.exit(1);
        }
    }

    initialize() {
        this.ws.on('connection', async (ws) => {
            console.log(`[${this.name}] New client connected`);
            ws.id = this.connectionsCounter++;
            await this.handleConnection(ws);
        });

        console.log(`[${this.name}] WebSocket server started on port ${this.port}`);
    }

    async handleConnection(ws) {
        ws.on("error", (error) => {
            console.error(`[${this.name}] WebSocket error:`, error.message);
        })

        messaging.getFullMessage(ws, async (message, destination, source, type) => {

            if (destination !== this.name && destination !== "BCAST") {
                await this.redirectPackage(ws, message, destination, source, type);
            } else if (destination === "BCAST") {
                const decrypted = this.handleProtectedMessage(ws, message, source);
                await this.sendBroadcastMessage(decrypted, source);
            } else {
                if (this.sessions[ws.id] === undefined) this.sessions[ws.id] = {};
                this.sessions[ws.id].source = source;

                switch (type) {
                    // receive HELLO message
                    case 1:
                        console.log(`[${this.name}] Received hello message`);
                        this.rememberClientNonce(ws, message)
                        console.log(`[${this.name}] Send hello response to client`);
                        await this.sendHelloResponse(ws);
                        break;
                    // receive Secret
                    case 3:
                        this.handleSecret(ws, message)
                        await this.sendReadyMessage(ws)
                        break;
                    // receive READY message
                    case 4:
                        this.handleFinishMessage(ws, message, source);
                        break;
                    // receive protected message
                    case 5:
                        this.handleProtectedMessage(ws, message, source)
                        break;
                }
            }
        });
    }

    async redirectPackage(ws, message, destination, source, type) {
        if (this.activeTunnels.has(ws)) {
            const destWs = this.activeTunnels.get(ws);
            await messaging.sendMessageInParts(destWs, message, destination, type, source, this.name);
            return;
        }

        if (this.routs.get(destination)) {
            const url = `ws://localhost:${this.routs.get(destination).server.port}`
            const destWs = new WebSocket(url);

            destWs.on('open', async () => {
                await messaging.sendMessageInParts(destWs, message, destination, type, source, this.name);

                await messaging.getFullMessage(destWs, async (message, destination, source, type) => {
                    await messaging.sendMessageInParts(ws, message, destination, type, source, this.name);
                });

                this.activeTunnels.set(ws, destWs);
            });

            destWs.on("error", (error) => {
                console.error(`[${this.name}] WebSocket error:`, error.message);
            })
        } else {
            console.error(`[${this.name}] there is no way to connect to node ${destination}`);
        }
    }

    rememberClientNonce(ws, message){
        const messageObj = JSON.parse(message);
        this.sessions[ws.id].clientNonce = Buffer.from(messageObj.nonce, 'base64');
    }

    async sendHelloResponse(ws) {
        try {
            const serverNonce = crypto.randomBytes(32);
            this.sessions[ws.id].serverNonce = serverNonce;
            const response = JSON.stringify({
                nonce: serverNonce.toString('base64'),
                certificate: this.certificate
            });
            await messaging.sendMessageInParts(ws, response, this.sessions[ws.id].source,2, this.name);
        } catch (error) {
            console.error(`[${this.name}] Error sending hello response:`, error.message);
            ws.close();
        }
    }

     handleSecret(ws, message) {
        try {
            const messageObj = JSON.parse(message);
            if (!messageObj.secret)
                throw new Error(`Secret is missing in message`);

            this.decryptSecret(ws, messageObj.secret);
            this.generateSessionKey(ws)
        } catch (error) {
            console.error(`[${this.name}] Error processing secret:`, error.message);
            ws.close();
        }
    }

    decryptSecret(ws, encryptedSecret) {
        try {
            const encryptedBuffer = Buffer.from(encryptedSecret, 'base64');
            this.sessions[ws.id].premaster = crypto.privateDecrypt(
                {
                    key: this.privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
                },
                encryptedBuffer
            );
            console.log(`[${this.name}] Successfully decrypted premaster secret`);
        } catch (error) {
            console.error(`[${this.name}] Error decrypting secret:`, error.message);
        }
    }

    generateSessionKey(ws) {
        try {
            this.sessions[ws.id].sessionKey = encryption.generateSessionKey(
                this.sessions[ws.id].premaster,
                this.sessions[ws.id].clientNonce,
                this.sessions[ws.id].serverNonce)
            console.error(`[${this.name}] Session key was successfully generated.`);
        } catch (error) {
            console.error(`[${this.name}] Error while generating session key:`, error.message);
        }
    }

    async sendReadyMessage(ws) {
        try {
            const message = "READY"
            const encryptedMessage = encryption.encryptMessage(this.sessions[ws.id].sessionKey, message)

            console.log(`[${this.name}] Send encrypted \"READY\" message to client`);
            await messaging.sendMessageInParts(ws, encryptedMessage, this.sessions[ws.id].source,4, this.name);
        } catch (error) {
            console.error(`[${this.name}] Error sending encrypted \"READY\" message to client.`, error.message);
            ws.close();
        }
    }

    handleFinishMessage(ws, message, source) {
        try {
            const decryptedMessage = encryption.decryptMessage(this.sessions[ws.id].sessionKey, message);
            this.sessions[ws.id].isConnectionSecure = decryptedMessage.toString() === "READY";
            if(!this.sessions[ws.id].isConnectionSecure)
                throw new Error("\"READY\" message was not recognised")
            this.connectedClients.set(source, ws);

            console.log(`[${this.name}] Received \"READY\" message from client`);
        } catch (error) {
            console.error(`[${this.name}] Error while handling client \"READY\" message:`, error.message);
            ws.close();
        }
    }

    handleProtectedMessage(ws, message, client) {
        try {
            const decryptedMessage = encryption.decryptMessage(this.sessions[ws.id].sessionKey, message).toString();
            console.log(`[${this.name}] Received \"${decryptedMessage}\" message from ${client}`);
            return decryptedMessage;
        } catch (error) {
            console.error(`[${this.name}] Error handling protected message:`, error.message);
        }
    }

    async sendMessageToClient(message, client) {
        try {
            const socket = this.connectedClients.get(client);
            if (!socket)
                throw new Error(`Client ${client} does not connected to this node`);

            if (!this.sessions[socket.id].isConnectionSecure)
                throw new Error(`Connection to client ${client} is unsecure`);

            const encryptedMessage = encryption.encryptMessage(this.sessions[socket.id].sessionKey, message)
            console.log(`[${this.name}] Send encrypted message to client ${client}`);
            await messaging.sendMessageInParts(socket, encryptedMessage, client, 5, this.name);

        } catch (error) {
            console.error(`[${this.name}] Error sending message to client:`, error.message);
        }
    }

    async sendBroadcastMessage(message, exciter = null) {
        try {
            for (const [node, connection] of this.connections) {
                if (connection === exciter) continue;
                await connection.sendBroadcastMessage(message);
            }

            for (const [client, socket] of this.connectedClients) {
                if (client === exciter) continue;
                if (!this.sessions[socket.id].isConnectionSecure)
                    throw new Error(`Connection to client ${client} is unsecure`);

                const encryptedMessage = encryption.encryptMessage(this.sessions[socket.id].sessionKey, message);
                await messaging.sendMessageInParts(socket, encryptedMessage, "BCAST", 0, this.name);
            }
        } catch (error) {
            console.error(`[${this.name}] Broadcast failed:`, error.message);
        }
    }

    updateRouts(routs){
        this.routs = routs;
    }

    setConnections(connections){
        this.connections = connections;
    }
}