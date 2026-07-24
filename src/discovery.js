// discovery.js
// LAN auto-discovery so the desktop app doesn't need the server's IP typed in
// manually. UDP because there's no auth/connection to piggyback on yet - this
// is how a client finds the server before it has any way to authenticate.
//
// Port 41234 (UDP) - deliberately distinct from the HTTP server's port
// (process.env.PORT || 4100, see server.js) so the two don't collide.
// Magic string "WILO_DISCOVER" - a client broadcasts this UDP packet on the
// LAN; any packet whose UTF-8 contents match it exactly gets a unicast JSON
// reply sent back to rinfo.address/rinfo.port (the packet's own source,
// never rebroadcast). We deliberately do NOT try to self-detect our own LAN
// IP (unreliable across multiple interfaces/VPNs) - the client uses the
// reply's source address, which is guaranteed reachable from the client's
// own perspective.
import dgram from "dgram";

const DISCOVERY_PORT = 41234;
const MAGIC = "WILO_DISCOVER";

export function startDiscoveryListener(httpPort) {
  const socket = dgram.createSocket("udp4");

  socket.on("message", (msg, rinfo) => {
    if (msg.toString("utf-8") !== MAGIC) return; // ignore anything that doesn't match exactly
    const reply = Buffer.from(JSON.stringify({ name: "wilo-server", httpPort }));
    socket.send(reply, rinfo.port, rinfo.address);
  });

  socket.on("error", (err) => {
    console.error("Discovery listener error:", err);
  });

  socket.bind(DISCOVERY_PORT, () => {
    console.log(`Wilo-Server discovery listening on UDP :${DISCOVERY_PORT}`);
  });

  return socket;
}
