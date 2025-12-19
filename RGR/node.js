import { Server } from './server.js'
import { Client } from './client.js'

export class Node {
    constructor(name, port) {
        this.name = name
        this.server = new Server(name, port)
        this.connections = new Map();
        this.routsTable = new Map();
        this.neighborNodes = [];

        this.server.setConnections(this.connections)
    }

    connectToNode(node) {
        const nextNode = this.routsTable.get(node.name);
        if (!nextNode) {
            console.error(`[${this.name}] there is no way to connect node ${node.name}`);
        }

        const connectionURL = `ws://localhost:${nextNode.server.port}`
        this.connections.set(node, new Client(this.name, connectionURL, node.name, this.server));
        return this.connections.get(node).handshakePromise;
    }

    disconnectFromNode(node) {
        this.connections[node].ws.close();
        this.connections.delete(node);
    }

    async sendMessageToNode(message, node) {
        const client = this.connections.get(node);
        if (client) await client.sendMessageToServer(message);
        else await this.server.sendMessageToClient(message, node.name);
    }

    async sendBroadcastMessage(message) {
        await this.server.sendBroadcastMessage(message);
    }

    addNeighborNode(node) {
        this.neighborNodes.push(node);
        node.neighborNodes.push(this);
    }

    prepareRoutesTable() {
        this.routsTable.clear();

        const visited = new Set([this]);
        const queue = [];

        for (const neighbor of this.neighborNodes) {
            this.routsTable.set(neighbor.name, neighbor);
            queue.push({ node: neighbor, base: neighbor });
            visited.add(neighbor);
        }

        while (queue.length > 0) {
            const { node, base } = queue.shift();

            for (const next of node.neighborNodes) {
                if (visited.has(next)) continue;

                this.routsTable.set(next.name, base);
                visited.add(next);
                queue.push({ node: next, base });
            }
        }

        this.server.updateRouts(this.routsTable);
    }
}