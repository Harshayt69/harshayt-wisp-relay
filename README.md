# Harshayt Wisp Relay

A small self-hosted **Wisp v1 WebSocket → TCP relay** intended for Eaglercraft/Wispcraft-style clients.

## What it does

```text
Eaglercraft/Wispcraft browser
          |
          | WebSocket / Wisp v1
          v
     This relay
          |
          | TCP
          v
   Java Minecraft server
```

Wisp defines CONNECT, DATA, CONTINUE, and CLOSE packets. The relay sends a Wisp v1 CONTINUE packet on stream 0 immediately after the WebSocket opens, then accepts TCP CONNECT streams and forwards raw bytes in both directions.

## Safety defaults

This implementation is intentionally **not** a completely open SSRF proxy:

- TCP only.
- Private, loopback, link-local, and unspecified IP destinations are blocked.
- A maximum number of WebSocket connections is enforced.
- A maximum number of streams per WebSocket is enforced.
- Connection attempts time out.
- Large WebSocket messages are capped.

Do not remove these protections unless you understand the security implications.

## Run locally

Requires Node.js 20+.

```bash
npm install
npm start
```

Default endpoint:

```text
ws://localhost:8080/wisp/
```

Health check:

```text
http://localhost:8080/health
```

## Configuration

Environment variables:

- `PORT` — default `8080`
- `HOST` — default `0.0.0.0`
- `WISP_PATH` — default `/wisp/`
- `BUFFER_PACKETS` — default `128`
- `MAX_STREAMS` — default `8`
- `MAX_CONNECTIONS` — default `50`
- `CONNECT_TIMEOUT_MS` — default `15000`
- `MAX_FRAME_BYTES` — default `1048576`

Example:

```bash
PORT=8080 MAX_STREAMS=4 MAX_CONNECTIONS=20 npm start
```

## HTTPS / public deployment

Browsers generally need a secure WebSocket endpoint when the page itself is HTTPS. Put this Node server behind a reverse proxy such as a normal TLS-terminating web server, and expose:

```text
wss://your-domain.example/wisp/
```

The reverse proxy must pass WebSocket upgrades.

## Important

This is the **relay backend**. Your Eaglercraft client still needs to be configured to use the relay's Wisp URL. The relay does not modify your 26.2 HTML automatically.

For a public deployment, add authentication/rate limiting and keep the private-address protection enabled.

## Protocol reference

The implementation follows the Wisp packet layout:

- byte 0: packet type
- bytes 1–4: little-endian stream ID
- remaining bytes: payload

The protocol's CONNECT payload is TCP/UDP type + little-endian port + UTF-8 hostname.

Reference: https://github.com/MercuryWorkshop/wisp-protocol
