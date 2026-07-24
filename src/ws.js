// Real-time broadcast to every connected client (desktop AND mobile) -
// replaces the Electron-hosted WebSocketServer entirely. Kept in its own
// module so routes/*.js can broadcast without importing server.js (circular).
const clients = new Set();

export function registerClient(ws) {
  clients.add(ws);
  ws.on("close", () => clients.delete(ws));
}

export function broadcast(type, payload) {
  const message = JSON.stringify({ type, payload });
  for (const ws of clients) {
    if (ws.readyState === ws.OPEN) ws.send(message);
  }
}
