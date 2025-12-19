const CHUNK_SIZE = 64;
const HEADER_SIZE = 13;
const DELAY = 100;

export function sendMessageInParts(socket, message, destination, type = 0, origin, source = null) {
    return new Promise((resolve, reject) => {
        const pckg = preparePackageForSending(message, destination, type, origin);
        let sentSize = 0;

        const intervalId = setInterval(() => {
            if (sentSize >= pckg.length) {
                clearInterval(intervalId);
                resolve();
                return;
            }

            const chunk = pckg.subarray(sentSize, sentSize + CHUNK_SIZE);
            sentSize += CHUNK_SIZE;

            try {
                socket.send(chunk);
                if (source) origin = source;
                console.log(`[${origin}] Sent ${chunk.length} bytes`);
            } catch (err) {
                clearInterval(intervalId);
                reject(err);
            }
        }, DELAY);
    });
}

function preparePackageForSending(message, destination, type, source) {
    const header = Buffer.alloc(HEADER_SIZE);
    header.write(destination,0);
    header.write(source, 5);
    header.writeUInt16LE(message.length, 10);
    header.writeUInt8(type, 12);
    const payload = Buffer.from(message, 'utf8');
    return Buffer.concat([header, payload]);
}

export function getFullMessage(socket, callback){
    let buffer = Buffer.alloc(0);

    socket.on("message", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);

        while (buffer.length >= HEADER_SIZE) {
            const payloadLength = buffer.readUInt16LE(10);
            const packetLength = HEADER_SIZE + payloadLength;

            if (buffer.length < packetLength) break;

            const destination = buffer.subarray(0, 5).toString().trim();
            const source = buffer.subarray(5, 10).toString().trim();
            const type = buffer.readUint8(12);
            const payload = buffer.subarray(HEADER_SIZE, packetLength);

            buffer = buffer.subarray(packetLength);

            callback(payload, destination, source, type);
        }
    });
}