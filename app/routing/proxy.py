from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlsplit
from typing import Any

from app.routing.selector import AdaptiveRouteSelector
from app.routing.state import MetricsStore


@dataclass
class Upstream:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    connect_ms: float


class ProxyError(Exception):
    pass


class BlockedDestination(ProxyError):
    pass


async def _read_header(reader: asyncio.StreamReader) -> bytes:
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
    except asyncio.LimitOverrunError as exc:
        raise ProxyError("HTTP headers are too large") from exc
    except asyncio.IncompleteReadError as exc:
        raise ProxyError("Client closed before sending complete headers") from exc
    if len(data) > 65536:
        raise ProxyError("HTTP headers are too large")
    return data


def _request_line_and_headers(header: bytes) -> tuple[str, list[tuple[str, str]]]:
    try:
        lines = header.decode("iso-8859-1").split("\r\n")
    except UnicodeDecodeError as exc:
        raise ProxyError("Invalid HTTP headers") from exc
    if not lines or len(lines[0].split(" ", 2)) != 3:
        raise ProxyError("Malformed HTTP request line")
    parsed_headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            break
        if line[:1] in (" ", "\t") or ":" not in line:
            raise ProxyError("Malformed HTTP header")
        name, value = line.split(":", 1)
        parsed_headers.append((name.strip(), value.strip()))
    return lines[0], parsed_headers


def _host_port(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise ProxyError("Invalid IPv6 authority")
        host = authority[1:closing]
        rest = authority[closing + 1:]
        if rest.startswith(":"):
            port = int(rest[1:])
        elif rest == "":
            port = default_port
        else:
            raise ProxyError("Invalid IPv6 authority")
    else:
        if authority.count(":") > 1:
            host, port = authority, default_port
        elif ":" in authority:
            host, port_text = authority.rsplit(":", 1)
            port = int(port_text)
        else:
            host, port = authority, default_port
    if not host or not 1 <= int(port) <= 65535:
        raise ProxyError("Invalid destination host or port")
    return host, int(port)


def _prepare_http_request(header: bytes, for_upstream: bool = True) -> tuple[str, int, bytes, bool, str]:
    request_line, headers = _request_line_and_headers(header)
    method, target, version = request_line.split(" ", 2)
    parsed = urlsplit(target)
    if parsed.scheme.lower() != "http" or not parsed.hostname:
        raise ProxyError("Only absolute-form HTTP URLs are supported for non-CONNECT requests")
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    body_header = any(name.lower() == "transfer-encoding" and value.lower() != "identity"
                      for name, value in headers)
    content_length = 0
    for name, value in headers:
        if name.lower() == "content-length":
            try:
                content_length = max(content_length, int(value))
            except ValueError:
                raise ProxyError("Invalid Content-Length")
    has_body = body_header or content_length > 0
    safe_retry = method.upper() in {"GET", "HEAD", "OPTIONS"} and not has_body
    if for_upstream:
        new_line = f"{method} {path} {version}"
        new_headers: list[tuple[str, str]] = []
        has_host = False
        for name, value in headers:
            lower_name = name.lower()
            if lower_name in {"proxy-connection", "connection", "keep-alive"}:
                continue
            if lower_name == "host":
                has_host = True
            new_headers.append((name, value))
        if not has_host:
            default_port = 80
            host_value = f"[{host}]" if ":" in host else host
            if port != default_port:
                host_value += f":{port}"
            new_headers.append(("Host", host_value))
        new_headers.append(("Connection", "close"))
        output = new_line + "\r\n" + "".join(f"{name}: {value}\r\n" for name, value in new_headers) + "\r\n"
        output_bytes = output.encode("iso-8859-1")
    else:
        output_bytes = header
    return host, port, output_bytes, safe_retry, method.upper()


def _safe_tls_client_hello_replay(data: bytes | bytearray) -> bytes | None:
    """Return a replayable first TLS ClientHello record, never early application data.

    Replaying arbitrary pre-response bytes could duplicate TLS 1.3 0-RTT application
    data. Be conservative: only one initial handshake record (complete or partial)
    may be replayed. If extra bytes/records have already been sent, close this
    connection and let the browser retry using the newly learned route.
    """
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
        return None
    record_length = int(data[3:5].hex(), 16)
    record_end = 5 + record_length
    if len(data) > record_end:
        return None
    return bytes(data)


async def _resolve_destination(host: str, port: int) -> tuple[str, bool, float]:
    """Resolve on the client so VPS routing does not bypass client-side AdGuard DNS."""
    started = time.monotonic()
    try:
        literal = ipaddress.ip_address(host)
        if literal.is_unspecified:
            raise BlockedDestination("Destination resolved to an unspecified address (likely blocked by DNS filtering).")
        return str(literal), literal.is_global, (time.monotonic() - started) * 1000
    except ValueError:
        pass
    try:
        answers = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=4
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise ProxyError(f"DNS resolution failed for {host}") from exc
    addresses: list[tuple[int, str, bool]] = []
    seen: set[str] = set()
    for family, _socktype, _proto, _canonname, sockaddr in answers:
        address = sockaddr[0]
        if address in seen:
            continue
        seen.add(address)
        parsed = ipaddress.ip_address(address)
        if parsed.is_unspecified:
            raise BlockedDestination(f"DNS policy returned {address} for {host}; the destination will not be sent to the VPS.")
        addresses.append((family, address, parsed.is_global))
    if not addresses:
        raise ProxyError(f"DNS returned no addresses for {host}")
    # Prefer public IPv4 when available; use IPv6 if it is the only public family.
    public_addresses = [item for item in addresses if item[2]]
    ipv4_public = [item for item in public_addresses if item[0] == socket.AF_INET]
    selected = (ipv4_public or public_addresses or
                [item for item in addresses if item[0] == socket.AF_INET] or addresses)[0]
    return selected[1], selected[2], (time.monotonic() - started) * 1000


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def _cancel_task(task: asyncio.Task[Any] | None) -> None:
    if task is not None and not task.done():
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


class BrowserProxy:
    def __init__(self, store: MetricsStore, selector: AdaptiveRouteSelector,
                 vps_host: str | None = None, vps_port: int | None = None,
                 connect_timeout: float | None = None,
                 first_byte_timeout: float | None = None) -> None:
        self.store = store
        self.selector = selector
        self.vps_host = vps_host or os.getenv("NETBOOST_VPS_PROXY_HOST", "10.8.0.1")
        self.vps_port = vps_port or int(os.getenv("NETBOOST_VPS_PROXY_PORT", "8765"))
        self.connect_timeout = connect_timeout or float(os.getenv("NETBOOST_CONNECT_TIMEOUT", "4"))
        self.first_byte_timeout = first_byte_timeout or float(os.getenv("NETBOOST_FIRST_BYTE_TIMEOUT", "5"))
        self._path_cache: dict[str, Any] | None = None
        self._path_cache_at = 0.0
        self._path_lock = asyncio.Lock()

    async def path_status(self, refresh: bool = False) -> dict[str, Any]:
        if not refresh and self._path_cache is not None and time.monotonic() - self._path_cache_at < 5:
            return self._path_cache
        async with self._path_lock:
            if not refresh and self._path_cache is not None and time.monotonic() - self._path_cache_at < 5:
                return self._path_cache
            direct_device = await self._route_device("1.1.1.1")
            tunnel_device = await self._route_device("10.8.0.1")
            vps_port_open = False
            if tunnel_device == "wg0":
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.vps_host, self.vps_port), timeout=1.2
                    )
                    writer.write(b"GET /health HTTP/1.1\r\nHost: netboost.local\r\nConnection: close\r\n\r\n")
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
                    health_response = await asyncio.wait_for(_read_header(reader), timeout=1.0)
                    vps_port_open = health_response.startswith(b"HTTP/1.1 200 ")
                    await _close_writer(writer)
                except (OSError, asyncio.TimeoutError):
                    vps_port_open = False
            status = {
                "direct_device": direct_device,
                "tunnel_device": tunnel_device,
                "direct_route_ready": bool(direct_device and direct_device != "wg0"),
                "wireguard_route_ready": tunnel_device == "wg0",
                "vps_proxy_ready": vps_port_open,
                "ready": bool(direct_device and direct_device != "wg0" and tunnel_device == "wg0" and vps_port_open),
                "note": None,
            }
            if not status["direct_route_ready"]:
                status["note"] = "The default route still uses wg0. Configure the client as a split tunnel before using NetBoost; otherwise the direct route would secretly travel through WireGuard."
            elif not status["wireguard_route_ready"]:
                status["note"] = "The 10.8.0.1 route does not use wg0. Bring up the WireGuard tunnel to make the VPS route available."
            elif not status["vps_proxy_ready"]:
                status["note"] = f"The WireGuard route is present, but the VPS proxy at {self.vps_host}:{self.vps_port} is not reachable yet."
            self._path_cache = status
            self._path_cache_at = time.monotonic()
            return status

    async def _route_device(self, destination: str) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "-4", "route", "get", destination,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1.5)
            if proc.returncode != 0:
                return None
            tokens = stdout.decode("utf-8", "replace").strip().split()
            if "dev" in tokens:
                return tokens[tokens.index("dev") + 1]
        except (OSError, asyncio.TimeoutError):
            return None
        return None

    async def handle(self, client_reader: asyncio.StreamReader,
                     client_writer: asyncio.StreamWriter) -> None:
        peer = client_writer.get_extra_info("peername")
        try:
            environment = await self.path_status()
            if not environment["direct_route_ready"]:
                self.store.add_event("configuration_error", "Refused browser connection: direct route is not independent of WireGuard.",
                                     environment=environment)
                await self._send_error(client_writer, 503, "NetBoost split tunnel is not configured", environment.get("note") or "Check WireGuard AllowedIPs.")
                return
            header = await _read_header(client_reader)
            request_line, _ = _request_line_and_headers(header)
            method, target, _version = request_line.split(" ", 2)
            if method.upper() == "CONNECT":
                host, port = _host_port(target, 443)
                await self._handle_connect(host, port, client_reader, client_writer)
            else:
                host, port, outgoing_header, safe_retry, http_method = _prepare_http_request(header)
                await self._handle_http(host, port, outgoing_header, safe_retry, http_method,
                                        client_reader, client_writer)
        except asyncio.CancelledError:
            raise
        except BlockedDestination as exc:
            self.store.add_event("dns_block", str(exc))
            with contextlib.suppress(Exception):
                await self._send_error(client_writer, 403, "Blocked by NetBoost DNS policy", str(exc))
        except ProxyError as exc:
            self.store.add_event("proxy_error", str(exc))
            with contextlib.suppress(Exception):
                await self._send_error(client_writer, 400, "Bad proxy request", str(exc))
        except (OSError, asyncio.TimeoutError, ConnectionError) as exc:
            self.store.add_event("proxy_error", f"Connection error from {peer}: {type(exc).__name__}: {exc}")
            with contextlib.suppress(Exception):
                await self._send_error(client_writer, 502, "Bad gateway", "The selected route could not establish the connection.")
        except Exception as exc:
            self.store.add_event("proxy_error", f"Unexpected proxy error: {type(exc).__name__}: {exc}")
            with contextlib.suppress(Exception):
                await self._send_error(client_writer, 502, "Bad gateway", "NetBoost could not complete this request.")
        finally:
            await _close_writer(client_writer)

    async def _open_target(self, route: str, host: str, port: int) -> Upstream:
        started = time.monotonic()
        if route == "direct":
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, limit=65536), timeout=self.connect_timeout
            )
            return Upstream(reader, writer, (time.monotonic() - started) * 1000)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.vps_host, self.vps_port, limit=65536), timeout=self.connect_timeout
        )
        try:
            authority_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
            writer.write(f"CONNECT {authority_host}:{port} HTTP/1.1\r\nHost: {authority_host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n".encode("ascii"))
            await asyncio.wait_for(writer.drain(), timeout=self.connect_timeout)
            response = await asyncio.wait_for(_read_header(reader), timeout=self.connect_timeout)
            first_line = response.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
            fields = first_line.split(" ", 2)
            if len(fields) < 2 or fields[1] != "200":
                raise ProxyError(f"VPS proxy rejected {host}:{port}: {first_line}")
            return Upstream(reader, writer, (time.monotonic() - started) * 1000)
        except BaseException:
            await _close_writer(writer)
            raise

    async def _handle_connect(self, host: str, port: int,
                              client_reader: asyncio.StreamReader,
                              client_writer: asyncio.StreamWriter) -> None:
        started = time.monotonic()
        connect_host, public_destination, dns_ms = await _resolve_destination(host, port)
        route, reason = self.selector.choose(host)
        if not public_destination:
            route, reason = "direct", "destination is non-public; VPS routing is disabled to protect local/private networks"
        self.store.add_event("connection", f"CONNECT {host}:{port} starts on {route}: {reason}", host, route, dns_ms=round(dns_ms, 2), connect_host=connect_host)
        other = "vps" if route == "direct" else "direct"
        candidates = (route, other) if public_destination else ("direct",)
        upstream: Upstream | None = None
        active_route = route
        for candidate in candidates:
            try:
                upstream = await self._open_target(candidate, connect_host, port)
                active_route = candidate
                if candidate != route:
                    self.store.add_event("fallback", f"Route setup failed; switched {route} -> {candidate} before opening the browser tunnel.", host, candidate)
                break
            except (OSError, asyncio.TimeoutError, ProxyError, ConnectionError) as exc:
                elapsed = (time.monotonic() - started) * 1000
                self.store.record_attempt(host, candidate, outcome="failure", connect_ms=elapsed,
                                          reason=f"setup_failed: {type(exc).__name__}")
                self.store.add_event("route_failure", f"{candidate} could not establish {host}:{port}; trying the alternative route.", host, candidate,
                                     error=f"{type(exc).__name__}: {exc}")
        if upstream is None:
            await self._send_error(client_writer, 502, "Bad gateway", f"Both routes failed to connect to {host}:{port}.")
            return

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: NetBoost\r\n\r\n")
        try:
            await client_writer.drain()
        except (OSError, ConnectionError):
            await _close_writer(upstream.writer)
            return
        initial_buffer = bytearray()
        max_attempts = 2
        setup_ms = upstream.connect_ms
        first_result: tuple[bytes | None, asyncio.Task[bytes] | None, float, int, str] | None = None
        for attempt_index in range(max_attempts):
            try:
                first_result = await self._wait_connect_first_response(
                    client_reader, upstream.reader, upstream.writer, initial_buffer,
                    self.first_byte_timeout, initial_already_sent=bool(initial_buffer) and attempt_index > 0
                )
            except asyncio.CancelledError:
                await _close_writer(upstream.writer)
                raise
            except Exception as exc:
                self.store.add_event("tunnel_error", f"Error before the first TLS server data for {host}: {type(exc).__name__}: {exc}", host, active_route)
                await _close_writer(upstream.writer)
                return
            response_bytes, pending_client_task, first_byte_ms, upstream_bytes, result = first_result
            if response_bytes:
                record_id = self.store.record_attempt(host, active_route, outcome="success",
                                                      connect_ms=setup_ms, first_byte_ms=first_byte_ms,
                                                      reason="", up_bytes=upstream_bytes,
                                                      down_bytes=len(response_bytes),
                                                      duration_ms=(time.monotonic() - started) * 1000)
                self.store.add_event("connected", f"{host} is responding through {active_route}; first server data arrived in {first_byte_ms:.0f} ms after client data.", host, active_route,
                                     connect_ms=round(setup_ms, 2), first_byte_ms=round(first_byte_ms, 2))
                counts = [upstream_bytes, len(response_bytes)]
                session_start = time.monotonic()
                try:
                    client_writer.write(response_bytes)
                    await client_writer.drain()
                    await self._relay(client_reader, client_writer, upstream.reader, upstream.writer,
                                      counts, pending_client_task=pending_client_task)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.store.add_event("tunnel_error", f"TLS tunnel ended unexpectedly for {host}: {type(exc).__name__}: {exc}", host, active_route)
                finally:
                    self.store.complete_attempt(record_id, up_bytes=counts[0], down_bytes=counts[1],
                                                duration_ms=(time.monotonic() - session_start) * 1000)
                    await _close_writer(upstream.writer)
                return
            if result in {"client_idle", "client_closed_before_response"}:
                await _close_writer(upstream.writer)
                return
            elapsed = (time.monotonic() - started) * 1000
            self.store.record_attempt(host, active_route, outcome="failure", connect_ms=setup_ms,
                                      first_byte_ms=first_byte_ms if first_byte_ms else None,
                                      reason=result, up_bytes=upstream_bytes,
                                      duration_ms=elapsed)
            self.store.add_event("route_failure", f"{active_route} established TCP but produced no server data in time for {host}; attempting the alternative route.", host, active_route,
                                 failure=result)
            await _close_writer(upstream.writer)
            if attempt_index == max_attempts - 1:
                self.store.add_event("route_failure", f"Both routes failed before TLS server data arrived for {host}; the browser tunnel is being closed.", host, active_route)
                return
            if not public_destination:
                self.store.add_event("route_failure", f"Direct route timed out for non-public destination {host}; VPS fallback is intentionally disabled.", host, active_route)
                return
            replay_data = _safe_tls_client_hello_replay(initial_buffer)
            if replay_data is None:
                self.store.add_event("recovery_skipped", f"Did not replay pre-response data for {host}: it was not limited to a safe initial TLS ClientHello record. The browser can retry on a new connection.", host, active_route)
                return
            initial_buffer = bytearray(replay_data)
            active_route = "vps" if active_route == "direct" else "direct"
            try:
                upstream = await self._open_target(active_route, connect_host, port)
                setup_ms = upstream.connect_ms
                if initial_buffer:
                    upstream.writer.write(initial_buffer)
                    await asyncio.wait_for(upstream.writer.drain(), timeout=self.connect_timeout)
            except (OSError, asyncio.TimeoutError, ProxyError, ConnectionError) as exc:
                self.store.record_attempt(host, active_route, outcome="failure",
                                          connect_ms=(time.monotonic() - started) * 1000,
                                          reason=f"fallback_setup_failed: {type(exc).__name__}",
                                          up_bytes=len(initial_buffer))
                self.store.add_event("route_failure", f"Fallback route {active_route} also failed for {host}; the browser tunnel is being closed.", host, active_route,
                                     error=f"{type(exc).__name__}: {exc}")
                return
            self.store.add_event("fallback", f"First-response timeout; replayed the initial TLS data over {active_route}.", host, active_route,
                                 previous_route="vps" if active_route == "direct" else "direct")

    async def _wait_connect_first_response(
        self, client_reader: asyncio.StreamReader,
        upstream_reader: asyncio.StreamReader, upstream_writer: asyncio.StreamWriter,
        initial_buffer: bytearray, response_timeout: float,
        initial_already_sent: bool = False
    ) -> tuple[bytes | None, asyncio.Task[bytes] | None, float, int, str]:
        client_task: asyncio.Task[bytes] | None = asyncio.create_task(client_reader.read(65536))
        response_task: asyncio.Task[bytes] = asyncio.create_task(upstream_reader.read(65536))
        first_client_at: float | None = time.monotonic() if initial_already_sent and initial_buffer else None
        upstream_bytes = len(initial_buffer) if initial_already_sent else 0
        keep_client_task = False
        try:
            while True:
                if first_client_at is not None:
                    wait_timeout = max(0.0, response_timeout - (time.monotonic() - first_client_at))
                    if wait_timeout == 0:
                        return None, None, response_timeout * 1000, upstream_bytes, "first_byte_timeout"
                else:
                    wait_timeout = 60.0
                waiting: set[asyncio.Task[Any]] = {response_task}
                if client_task is not None:
                    waiting.add(client_task)
                done, _pending = await asyncio.wait(waiting, timeout=wait_timeout,
                                                   return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    if first_client_at is None:
                        return None, None, 0.0, upstream_bytes, "client_idle"
                    return None, None, response_timeout * 1000, upstream_bytes, "first_byte_timeout"

                # If client and server become readable together, forward the client
                # bytes before deciding whether the server has responded.
                if client_task is not None and client_task in done:
                    data = client_task.result()
                    client_task = None
                    if not data:
                        return None, None, 0.0, upstream_bytes, "client_closed_before_response"
                    initial_buffer.extend(data)
                    first_client_at = first_client_at or time.monotonic()
                    upstream_writer.write(data)
                    await asyncio.wait_for(upstream_writer.drain(), timeout=self.connect_timeout)
                    upstream_bytes += len(data)
                    client_task = asyncio.create_task(client_reader.read(65536))

                if response_task in done:
                    data = response_task.result()
                    if not data:
                        elapsed = (time.monotonic() - first_client_at) * 1000 if first_client_at else 0.0
                        return None, None, elapsed, upstream_bytes, "upstream_closed_before_response"
                    first_byte_ms = (time.monotonic() - first_client_at) * 1000 if first_client_at else 0.0
                    keep_client_task = True
                    return data, client_task, first_byte_ms, upstream_bytes, "success"
        finally:
            await _cancel_task(response_task)
            if not keep_client_task:
                await _cancel_task(client_task)

    async def _handle_http(self, host: str, port: int, outgoing_header: bytes,
                           safe_retry: bool, method: str,
                           client_reader: asyncio.StreamReader,
                           client_writer: asyncio.StreamWriter) -> None:
        started = time.monotonic()
        connect_host, public_destination, dns_ms = await _resolve_destination(host, port)
        route, reason = self.selector.choose(host)
        if not public_destination:
            route, reason = "direct", "destination is non-public; VPS routing is disabled to protect local/private networks"
        self.store.add_event("connection", f"HTTP {method} {host}:{port} starts on {route}: {reason}", host, route, dns_ms=round(dns_ms, 2), connect_host=connect_host)
        other = "vps" if route == "direct" else "direct"
        candidates = (route, other) if public_destination else ("direct",)
        upstream: Upstream | None = None
        active_route = route
        for candidate in candidates:
            try:
                upstream = await self._open_target(candidate, connect_host, port)
                active_route = candidate
                if candidate != route:
                    self.store.add_event("fallback", f"Route setup failed; switched {route} -> {candidate} before sending the HTTP request.", host, candidate)
                break
            except (OSError, asyncio.TimeoutError, ProxyError, ConnectionError) as exc:
                self.store.record_attempt(host, candidate, outcome="failure",
                                          connect_ms=(time.monotonic() - started) * 1000,
                                          reason=f"setup_failed: {type(exc).__name__}")
                self.store.add_event("route_failure", f"{candidate} could not connect to {host}:{port}; trying the alternative.", host, candidate,
                                     error=f"{type(exc).__name__}: {exc}")
        if upstream is None:
            await self._send_error(client_writer, 502, "Bad gateway", f"Both routes failed to connect to {host}:{port}.")
            return

        try:
            upstream.writer.write(outgoing_header)
            await asyncio.wait_for(upstream.writer.drain(), timeout=self.connect_timeout)
        except Exception:
            await _close_writer(upstream.writer)
            raise
        first_response: bytes | None = None
        first_byte_ms: float | None = None
        if safe_retry:
            for attempt_index in range(2):
                wait_started = time.monotonic()
                try:
                    first_response = await asyncio.wait_for(upstream.reader.read(65536), timeout=self.first_byte_timeout)
                    first_byte_ms = (time.monotonic() - wait_started) * 1000
                except asyncio.TimeoutError:
                    first_response = None
                if first_response:
                    break
                self.store.record_attempt(host, active_route, outcome="failure",
                                          connect_ms=upstream.connect_ms,
                                          first_byte_ms=self.first_byte_timeout * 1000,
                                          reason="first_byte_timeout")
                self.store.add_event("route_failure", f"{active_route} did not return an HTTP response in {self.first_byte_timeout:g} s for {host}.", host, active_route)
                await _close_writer(upstream.writer)
                if attempt_index == 1:
                    await self._send_error(client_writer, 504, "Gateway timeout", f"Neither route returned an HTTP response for {host}.")
                    return
                active_route = "vps" if active_route == "direct" else "direct"
                if not public_destination:
                    await self._send_error(client_writer, 504, "Gateway timeout", f"Direct route timed out for non-public destination {host}; VPS fallback is disabled.")
                    return
                try:
                    upstream = await self._open_target(active_route, connect_host, port)
                    upstream.writer.write(outgoing_header)
                    await asyncio.wait_for(upstream.writer.drain(), timeout=self.connect_timeout)
                except (OSError, asyncio.TimeoutError, ProxyError, ConnectionError) as exc:
                    await _close_writer(upstream.writer if upstream is not None else None)
                    self.store.record_attempt(host, active_route, outcome="failure",
                                              connect_ms=(time.monotonic() - started) * 1000,
                                              reason=f"fallback_setup_failed: {type(exc).__name__}")
                    self.store.add_event("route_failure", f"Fallback route {active_route} failed for {host}.", host, active_route,
                                         error=f"{type(exc).__name__}: {exc}")
                    await self._send_error(client_writer, 502, "Bad gateway", f"Fallback route failed for {host}.")
                    return
                self.store.add_event("fallback", f"Replayed idempotent {method} request through {active_route} after a response timeout.", host, active_route)
        else:
            # Requests which may carry a body are never replayed after transmission.
            # Relay immediately to avoid blocking POST/PUT bodies while waiting.
            counts = [len(outgoing_header), 0]
            session_start = time.monotonic()
            record_id: str | None = None
            try:
                await self._relay(client_reader, client_writer, upstream.reader, upstream.writer, counts)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.store.add_event("http_stream_error", f"HTTP stream ended unexpectedly for {host}: {type(exc).__name__}: {exc}", host, active_route)
            finally:
                await _close_writer(upstream.writer)
            return

        if first_response is None:
            raise ProxyError(f"No HTTP response from {host}")
        record_id = self.store.record_attempt(host, active_route, outcome="success",
                                              connect_ms=upstream.connect_ms,
                                              first_byte_ms=first_byte_ms,
                                              down_bytes=len(first_response),
                                              duration_ms=(time.monotonic() - started) * 1000)
        self.store.add_event("connected", f"HTTP response from {host} arrived through {active_route} in {first_byte_ms:.0f} ms.", host, active_route,
                             connect_ms=round(upstream.connect_ms, 2), first_byte_ms=round(first_byte_ms or 0, 2))
        counts = [len(outgoing_header), len(first_response)]
        session_start = time.monotonic()
        try:
            client_writer.write(first_response)
            await client_writer.drain()
            await self._relay(client_reader, client_writer, upstream.reader, upstream.writer, counts)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.store.add_event("http_stream_error", f"HTTP stream ended unexpectedly for {host}: {type(exc).__name__}: {exc}", host, active_route)
        finally:
            self.store.complete_attempt(record_id, up_bytes=counts[0], down_bytes=counts[1],
                                        duration_ms=(time.monotonic() - session_start) * 1000)
            await _close_writer(upstream.writer)

    async def _relay(self, client_reader: asyncio.StreamReader,
                     client_writer: asyncio.StreamWriter,
                     upstream_reader: asyncio.StreamReader,
                     upstream_writer: asyncio.StreamWriter,
                     counts: list[int],
                     pending_client_task: asyncio.Task[bytes] | None = None) -> None:
        async def copy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       count_index: int, pending: asyncio.Task[bytes] | None = None) -> None:
            current = pending
            while True:
                if current is not None:
                    data = await current
                    current = None
                else:
                    data = await reader.read(65536)
                if not data:
                    return
                writer.write(data)
                await writer.drain()
                counts[count_index] += len(data)

        tasks = [
            asyncio.create_task(copy(client_reader, upstream_writer, 0, pending_client_task)),
            asyncio.create_task(copy(upstream_reader, client_writer, 1)),
        ]
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

    async def _send_error(self, writer: asyncio.StreamWriter, status: int,
                          title: str, detail: str) -> None:
        safe_detail = detail.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        body = (f"{title}\n\n{safe_detail}\n").encode("utf-8", "replace")
        reason = {400: "Bad Request", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout"}.get(status, "Error")
        writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii") + body)
        with contextlib.suppress(Exception):
            await writer.drain()
