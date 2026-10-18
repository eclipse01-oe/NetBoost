#!/usr/bin/env python3
"""NetBoost's small CONNECT relay. Bind only to the WireGuard address (10.8.0.1)."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import logging
import socket
import time
from urllib.parse import urlsplit

LOG = logging.getLogger("netboost-vps-proxy")
HEADER_LIMIT = 65536


class RelayError(Exception):
    pass


async def read_header(reader: asyncio.StreamReader) -> bytes:
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError) as exc:
        raise RelayError("invalid or incomplete proxy headers") from exc
    if len(data) > HEADER_LIMIT:
        raise RelayError("proxy header too large")
    return data


def parse_connect(data: bytes) -> tuple[str, int]:
    try:
        lines = data.decode("iso-8859-1").split("\r\n")
        fields = lines[0].split(" ", 2)
    except Exception as exc:
        raise RelayError("malformed request") from exc
    if len(fields) != 3 or fields[0].upper() != "CONNECT" or not fields[2].startswith("HTTP/"):
        raise RelayError("only CONNECT requests are supported")
    authority = fields[1]
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise RelayError("invalid IPv6 target")
        host = authority[1:end]
        tail = authority[end + 1:]
        if not tail.startswith(":"):
            raise RelayError("destination port is required")
        port = int(tail[1:])
    else:
        if ":" not in authority:
            raise RelayError("destination port is required")
        host, port_text = authority.rsplit(":", 1)
        port = int(port_text)
    if not host or not 1 <= port <= 65535:
        raise RelayError("invalid destination")
    return host, port


def is_disallowed_literal(host: str) -> bool:
    lowered = host.rstrip(".").lower()
    if lowered in {"localhost", "localhost.localdomain"} or lowered.endswith(".localhost") or lowered.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return not address.is_global


async def open_public_target(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if is_disallowed_literal(host):
        raise RelayError("local/private literal destinations are not permitted")
    # Check DNS answers as a basic guard against the relay being used to reach
    # internal services. The listener is private to WireGuard, not public-facing.
    try:
        try:
            answers = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
                host, port, family=socket.AF_INET, type=socket.SOCK_STREAM
            ), timeout=4)
        except OSError:
            answers = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
                host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM
            ), timeout=4)
    except (OSError, asyncio.TimeoutError) as exc:
        raise RelayError("destination DNS lookup failed") from exc
    addresses = list(dict.fromkeys(item[4][0] for item in answers))
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise RelayError("destination resolved to a non-public address")
    # Prefer IPv4 for this first deployment and use the first validated answer
    # directly to reduce the DNS-rebinding window.
    address = addresses[0]
    try:
        parsed_ip = ipaddress.ip_address(address)
        family = socket.AF_INET6 if parsed_ip.version == 6 else socket.AF_INET
        return await asyncio.wait_for(asyncio.open_connection(address, port, family=family), timeout=4)
    except (OSError, asyncio.TimeoutError) as exc:
        raise RelayError("destination connection failed") from exc


async def close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                remote_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter) -> None:
    async def copy(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
        while True:
            data = await source.read(65536)
            if not data:
                return
            destination.write(data)
            await destination.drain()

    tasks = [asyncio.create_task(copy(reader, remote_writer)),
             asyncio.create_task(copy(remote_reader, writer))]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                task.result()
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    remote_writer: asyncio.StreamWriter | None = None
    started = time.monotonic()
    destination = "unknown"
    tunnel_established = False
    try:
        header = await read_header(reader)
        request_line = header.split(b"\r\n", 1)[0]
        if request_line == b"GET /health HTTP/1.1":
            body = b"NetBoost VPS relay ready\n"
            writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: "
                         + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
            await writer.drain()
            LOG.debug("health probe peer=%s", peer)
            return
        host, port = parse_connect(header)
        destination = f"{host}:{port}"
        remote_reader, remote_writer = await open_public_target(host, port)
        writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: NetBoost-VPS\r\n\r\n")
        await writer.drain()
        tunnel_established = True
        LOG.info("tunnel opened peer=%s destination=%s", peer, destination)
        await relay(reader, writer, remote_reader, remote_writer)
        LOG.info("tunnel ended destination=%s duration_ms=%.0f", destination, (time.monotonic() - started) * 1000)
    except asyncio.CancelledError:
        raise
    except (RelayError, OSError, asyncio.TimeoutError, ValueError) as exc:
        LOG.warning("tunnel rejected/failed peer=%s destination=%s reason=%s", peer, destination, exc)
        if not tunnel_established:
            with contextlib.suppress(Exception):
                body = b"NetBoost VPS relay could not establish the destination tunnel.\n"
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: "
                             + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
                await writer.drain()
    finally:
        await close_writer(remote_writer)
        await close_writer(writer)


async def run(host: str, port: int) -> None:
    server = await asyncio.start_server(handle, host, port, limit=HEADER_LIMIT)
    sockets = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    LOG.info("NetBoost VPS relay listening on %s", sockets)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="10.8.0.1", help="Bind address; keep this on the WireGuard interface")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(run(args.host, args.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
