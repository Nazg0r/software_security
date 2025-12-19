import { Node } from './node.js'
import { CertificateAuthority } from './CA/serverCA.js'

const serverCA = new CertificateAuthority(8090)

const nodeA = new Node("NodeA", 8080);
const nodeB = new Node("NodeB", 8081);
const nodeC = new Node("NodeC", 8082);
const nodeD = new Node("NodeD", 8083);
const nodeE = new Node("NodeE", 8084);

//  TOPOLOGY
//           D
//          /
// A - B - C
//          \
//           E

nodeA.addNeighborNode(nodeB);
nodeB.addNeighborNode(nodeC);
nodeC.addNeighborNode(nodeD);
nodeC.addNeighborNode(nodeE);

nodeA.prepareRoutesTable();
nodeB.prepareRoutesTable();
nodeC.prepareRoutesTable();
nodeD.prepareRoutesTable();
nodeE.prepareRoutesTable();

// TLS Handshake
await nodeA.connectToNode(nodeB);
await nodeA.sendMessageToNode("very secured message", nodeB);


// Unlinked node connection
// await nodeE.connectToNode(nodeA);
// await nodeE.sendMessageToNode("very secured message", nodeA);

// Broadcast
// await nodeA.connectToNode(nodeB);
// await nodeB.connectToNode(nodeC);
// await nodeC.connectToNode(nodeD);
// await nodeC.connectToNode(nodeE);
// await nodeC.sendBroadcastMessage("broadcastMessage");

