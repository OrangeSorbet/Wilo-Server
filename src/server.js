import express from "express";
import cors from "cors";
import http from "http";
import { WebSocketServer } from "ws";
import { db } from "./db/index.js";
import authRoutes from "./routes/auth.js";
import pairingRoutes from "./routes/pairing.js";
import roleRoutes from "./routes/roles.js";
import userRoutes from "./routes/users.js";
import sessionRoutes from "./routes/sessions.js";
import invoiceRoutes from "./routes/invoices.js";
import auditRoutes from "./routes/audit.js";
import { registerClient } from "./ws.js";
import { startDiscoveryListener } from "./discovery.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} from ${req.ip}`);
  next();
});

app.get("/", (req, res) => res.json({ ok: true, name: "wilo-server" }));
app.use("/auth", authRoutes);
app.use("/pairing", pairingRoutes);
app.use("/roles", roleRoutes);
app.use("/users", userRoutes);
app.use("/sessions", sessionRoutes);
app.use("/invoices", invoiceRoutes);
app.use("/audit", auditRoutes);

const PORT = process.env.PORT || 4100;
const server = http.createServer(app);

// WS auth: token passed as ?token= (ws library's verifyClient runs before
// the connection handler fires at all, matching the "reject before any
// state is created" posture used elsewhere in this design).
const wss = new WebSocketServer({
  server,
  verifyClient: (info, cb) => {
    const url = new URL(info.req.url, "http://localhost");
    const token = url.searchParams.get("token");
    if (!token) return cb(false, 401, "missing session token");
    const session = db.prepare("SELECT * FROM sessions WHERE id = ?").get(token);
    if (!session || new Date(session.expires_at).getTime() < Date.now()) {
      return cb(false, 401, "invalid or expired session");
    }
    cb(true);
  },
});

wss.on("connection", (ws) => registerClient(ws));

server.listen(PORT, () => console.log(`Wilo-Server listening on :${PORT}`));
startDiscoveryListener(PORT);
