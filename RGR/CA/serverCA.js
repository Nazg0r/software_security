import { WebSocketServer } from 'ws';
import { exec } from "child_process";
import fs from "fs";

export class CertificateAuthority {
    constructor(port) {
        this.port = port;
        this.rootCAPath = './CA/rootCA.crt';
        this.ws = new WebSocketServer({ port: port });
        this.initialize();
    }

    initialize() {
        if (!fs.existsSync(this.rootCAPath)) {
            console.error(`[CA] Root CA certificate not found at ${this.rootCAPath}`);
            process.exit(1);
        }

        this.ws.on('connection', (ws) => {
            console.log('[CA] New client connected');
            this.handleConnection(ws);
        });

        console.log(`[CA] Certificate Authority server started on port ${this.port}`);
    }

    handleConnection(ws) {
        ws.on('error', (error) =>
            console.error('[CA] WebSocket error:', error.message));

        ws.on('message', async (message) =>
            await this.handleVerificationRequest(ws, message));

        ws.on('close', () =>
            console.log('[CA] Client disconnected'));
    }

    async handleVerificationRequest(ws, message) {
        try {
            console.log('[CA] Received certificate verification request');

            const messageObj = JSON.parse(message);
            if (!messageObj.certificate)
                throw new Error('Certificate is missing in request');

            const result = await this.verifyCertificate(messageObj.certificate);
            ws.send(JSON.stringify(result));

        } catch (error) {
            console.error('[CA] Error handling verification request:', error.message);

            const errorResult = {
                isValid: false,
                message: `Error: ${error.message}`
            };

            ws.send(JSON.stringify(errorResult));
        }
    }

    verifyCertificate(certificate) {
        return new Promise((resolve) => {
            const tempCertName = `cert_${Date.now()}.crt`;

            try {
                fs.writeFileSync(tempCertName, certificate);
                console.log(`[CA] Temporary certificate written to ${tempCertName}`);

                const command = `openssl verify -CAfile "${this.rootCAPath}" "${tempCertName}"`;
                exec(command, (error, stdout, stderr) => {
                    this.cleanupTempFile(tempCertName);
                    const result = {
                        isValid: !error && stdout.includes('OK'),
                        message: error ? stderr.trim() : stdout.trim()
                    };

                    resolve(result);
                });
            } catch (error) {
                console.error('[CA] Error during certificate verification:', error.message);
                this.cleanupTempFile(tempCertName);

                resolve({
                    isValid: false,
                    message: `Error: ${error.message}`
                });
            }
        });
    }

    cleanupTempFile(filePath) {
        try {
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
                console.log(`[CA] Cleaned up temporary file: ${filePath}`);
            }
        } catch (error) {
            console.error(`[CA] Error cleaning up temp file ${filePath}:`, error.message);
        }
    }
}