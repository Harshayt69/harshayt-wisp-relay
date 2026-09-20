const http = require("http");
const net = require("net");
const dns = require("dns").promises;
const { WebSocketServer } = require("ws");

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "0.0.0.0";
const WISP_PATH = process.env.WISP_PATH || "/wisp/";
const BUFFER_PACKETS = Math.max(1, Number(process.env.BUFFER_PACKETS || 128));
const MAX_STREAMS = Math.max(1, Number(process.env.MAX_STREAMS || 8));
const MAX_CONNECTIONS = Math.max(1, Number(process.env.MAX_CONNECTIONS || 50));
const CONNECT_TIMEOUT_MS = Math.max(1000, Number(process.env.CONNECT_TIMEOUT_MS || 15000));
const MAX_FRAME_BYTES = Math.max(1024, Number(process.env.MAX_FRAME_BYTES || 1024 * 1024));

let activeConnections = 0;

const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok\n");
    return;
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("Wisp relay\n");
});

const wss = new WebSocketServer({
  noServer: true,
  maxPayload: MAX_FRAME_BYTES
});

server.on("upgrade", (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url || "/", "http://localhost");
  } catch {
    socket.destroy();
    return;
  }

  if (url.pathname !== WISP_PATH) {
    socket.destroy();
    return;
  }

  if (activeConnections >= MAX_CONNECTIONS) {
    socket.write("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, ws => {
    wss.emit("connection", ws, req);
  });
});

function packet(type, streamId, payload = Buffer.alloc(0)) {
  const out = Buffer.allocUnsafe(5 + payload.length);
  out.writeUInt8(type, 0);
  out.writeUInt32LE(streamId >>> 0, 1);
  payload.copy(out, 5);
  return out;
}

function sendPacket(ws, type, streamId, payload) {
  if (ws.readyState === ws.OPEN) {
    ws.send(packet(type, streamId, payload));
  }
}

function closeStream(ws, stream, reason = 0x03) {
  if (stream.closed) return;
  stream.closed = true;
  if (stream.socket) stream.socket.destroy();
  stream.socket = null;
  sendPacket(ws, 0x04, stream.id, Buffer.from([reason]));
  streams.delete(stream.id);
}

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(Number.isNaN)) return true;
  const [a,b,c] = p;
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function isPrivateIPv6(ip) {
  const x = ip.toLowerCase();
  return x === "::1" || x === "::" || x.startsWith("fc") || x.startsWith("fd") ||
         x.startsWith("fe8") || x.startsWith("fe9") || x.startsWith("fea") || x.startsWith("feb");
}

async function resolvePublicHost(host) {
  // Hostname/IP is supplied by the Wisp client. Resolve first, then reject
  // loopback/private/link-local destinations to avoid turning this into an SSRF relay.
  const records = await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length) throw new Error("unreachable");

  for (const r of records) {
    if ((r.family === 4 && isPrivateIPv4(r.address)) ||
        (r.family === 6 && isPrivateIPv6(r.address))) {
      throw new Error("blocked");
    }
  }
  return records[0].address;
}

const streams = new Map();

wss.on("connection", ws => {
  activeConnections++;
  const localStreams = new Set();

  // Wisp v1 compatibility: sending CONTINUE on stream 0 tells a client
  // to use the v1 protocol without requiring the v2 INFO handshake.
  sendPacket(ws, 0x03, 0, (() => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(BUFFER_PACKETS, 0);
    return b;
  })());

  const cleanup = () => {
    for (const id of localStreams) {
      const s = streams.get(id);
      if (s) {
        s.closed = true;
        if (s.socket) s.socket.destroy();
        streams.delete(id);
      }
    }
    activeConnections--;
  };

  ws.on("message", async (raw, isBinary) => {
    if (!isBinary) {
      ws.close(1003, "binary Wisp frames required");
      return;
    }

    const data = Buffer.from(raw);
    if (data.length < 5) {
      ws.close(1002, "invalid Wisp packet");
      return;
    }

    const type = data.readUInt8(0);
    const id = data.readUInt32LE(1);
    const payload = data.subarray(5);

    if (id === 0) {
      // v1 clients should not send normal stream packets on stream 0.
      return;
    }

    if (type === 0x01) {
      if (localStreams.size >= MAX_STREAMS || payload.length < 3) {
        sendPacket(ws, 0x04, id, Buffer.from([0x41]));
        return;
      }
      if (localStreams.has(id)) {
        sendPacket(ws, 0x04, id, Buffer.from([0x41]));
        return;
      }

      const streamType = payload.readUInt8(0);
      const port = payload.readUInt16LE(1);
      const hostBytes = payload.subarray(3);

      if (streamType !== 0x01 || port < 1 || port > 65535 || hostBytes.length === 0 || hostBytes.length > 253) {
        sendPacket(ws, 0x04, id, Buffer.from([0x41]));
        return;
      }

      const host = hostBytes.toString("utf8").trim();
      if (!host || host.includes("/") || host.includes("\0")) {
        sendPacket(ws, 0x04, id, Buffer.from([0x41]));
        return;
      }

      const stream = {
        id,
        socket: null,
        closed: false,
        clientPacketsSinceContinue: 0
      };
      streams.set(id, stream);
      localStreams.add(id);

      let address;
      try {
        address = await resolvePublicHost(host);
      } catch (e) {
        const reason = e && e.message === "blocked" ? 0x48 : 0x42;
        closeStream(ws, stream, reason);
        localStreams.delete(id);
        return;
      }

      const socket = net.createConnection({ host: address, port });
      stream.socket = socket;

      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          closeStream(ws, stream, 0x43);
          localStreams.delete(id);
        }
      }, CONNECT_TIMEOUT_MS);

      socket.on("connect", () => {
        if (stream.closed) return;
        settled = true;
        clearTimeout(timer);

        // Initial receive credit for the client->relay direction.
        const b = Buffer.alloc(4);
        b.writeUInt32LE(BUFFER_PACKETS, 0);
        sendPacket(ws, 0x03, id, b);
      });

      socket.on("data", chunk => {
        if (!stream.closed && ws.readyState === ws.OPEN) {
          // A TCP socket can produce arbitrarily sized chunks; each Wisp DATA
          // packet carries one chunk.
          sendPacket(ws, 0x02, id, Buffer.from(chunk));
        }
      });

      socket.on("error", err => {
        if (stream.closed) return;
        settled = true;
        clearTimeout(timer);
        const code = err && err.code === "ECONNREFUSED" ? 0x44 : 0x03;
        closeStream(ws, stream, code);
        localStreams.delete(id);
      });

      socket.on("close", () => {
        if (stream.closed) return;
        clearTimeout(timer);
        closeStream(ws, stream, 0x03);
        localStreams.delete(id);
      });

      return;
    }

    if (type === 0x02) {
      const stream = streams.get(id);
      if (!stream || stream.closed || !stream.socket) return;

      stream.socket.write(payload, err => {
        if (err) {
          closeStream(ws, stream, 0x03);
          localStreams.delete(id);
          return;
        }
        stream.clientPacketsSinceContinue++;
        if (stream.clientPacketsSinceContinue >= Math.max(1, Math.floor(BUFFER_PACKETS / 2))) {
          stream.clientPacketsSinceContinue = 0;
          const b = Buffer.alloc(4);
          b.writeUInt32LE(BUFFER_PACKETS, 0);
          sendPacket(ws, 0x03, id, b);
        }
      });
      return;
    }

    if (type === 0x04) {
      const stream = streams.get(id);
      if (stream) {
        stream.closed = true;
        if (stream.socket) stream.socket.destroy();
        streams.delete(id);
        localStreams.delete(id);
      }
      return;
    }

    // INFO is a v2 feature; this relay intentionally speaks the simpler v1
    // mode for compatibility with older Wispcraft/Eaglercraft clients.
  });

  ws.on("close", cleanup);
  ws.on("error", cleanup);
});

server.listen(PORT, HOST, () => {
  console.log(`Wisp v1 relay listening on ${HOST}:${PORT}${WISP_PATH}`);
});
