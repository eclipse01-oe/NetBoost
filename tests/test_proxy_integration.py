import asyncio

import pytest

from app.routing.proxy import BrowserProxy
from app.routing.selector import AdaptiveRouteSelector
from app.routing.state import MetricsStore


class LocalOnlyProxy(BrowserProxy):
    async def path_status(self, refresh: bool = False):
        return {"direct_route_ready": True, "wireguard_route_ready": False,
                "vps_proxy_ready": False, "note": None}


@pytest.mark.asyncio
async def test_local_proxy_forwards_plain_http_directly(tmp_path):
    async def origin_handler(reader, writer):
        request = await reader.readuntil(b"\r\n\r\n")
        assert request.startswith(b"GET /hello?from=netboost HTTP/1.1\r\n")
        body = b"netboost-proxy-test"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                     + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    origin = await asyncio.start_server(origin_handler, "127.0.0.1", 0)
    origin_port = origin.sockets[0].getsockname()[1]
    store = MetricsStore(tmp_path / "state.json")
    handler = LocalOnlyProxy(store, AdaptiveRouteSelector(store), first_byte_timeout=0.5)
    proxy = await asyncio.start_server(handler.handle, "127.0.0.1", 0)
    proxy_port = proxy.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write((f"GET http://127.0.0.1:{origin_port}/hello?from=netboost HTTP/1.1\r\n"
                      f"Host: 127.0.0.1:{origin_port}\r\n\r\n").encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=2)
        assert b"HTTP/1.1 200 OK" in response
        assert b"netboost-proxy-test" in response
        assert store.state["domains"]["127.0.0.1"]["direct"]
        writer.close()
        await writer.wait_closed()
    finally:
        proxy.close()
        origin.close()
        await proxy.wait_closed()
        await origin.wait_closed()


class SwitchingProxy(LocalOnlyProxy):
    def __init__(self, *args, slow_port: int, fast_port: int, **kwargs):
        super().__init__(*args, **kwargs)
        self.slow_port = slow_port
        self.fast_port = fast_port

    async def _open_target(self, route, host, port):
        from app.routing.proxy import Upstream
        target_port = self.slow_port if route == "direct" else self.fast_port
        reader, writer = await asyncio.open_connection("127.0.0.1", target_port)
        return Upstream(reader, writer, 1.0)


@pytest.mark.asyncio
async def test_https_tunnel_replays_initial_tls_data_over_alternative_route(tmp_path, monkeypatch):
    tls_body = b"\x01CLIENT_HELLO"
    tls_client_hello = b"\x16\x03\x01" + len(tls_body).to_bytes(2, "big") + tls_body

    async def slow_origin(reader, writer):
        try:
            await reader.read(4096)
            await asyncio.sleep(0.4)
            writer.write(b"TOO_LATE")
            await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def fast_origin(reader, writer):
        try:
            payload = await asyncio.wait_for(reader.read(4096), timeout=1)
            assert payload == tls_client_hello
            writer.write(b"FAST_SERVER_HELLO")
            await writer.drain()
            await asyncio.sleep(0.1)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    import app.routing.proxy as proxy_module

    async def fake_resolve(_host, _port):
        return "93.184.216.34", True, 0.1

    monkeypatch.setattr(proxy_module, "_resolve_destination", fake_resolve)
    slow = await asyncio.start_server(slow_origin, "127.0.0.1", 0)
    fast = await asyncio.start_server(fast_origin, "127.0.0.1", 0)
    slow_port = slow.sockets[0].getsockname()[1]
    fast_port = fast.sockets[0].getsockname()[1]
    store = MetricsStore(tmp_path / "state.json")
    handler = SwitchingProxy(store, AdaptiveRouteSelector(store), slow_port=slow_port,
                             fast_port=fast_port, first_byte_timeout=0.08)
    proxy = await asyncio.start_server(handler.handle, "127.0.0.1", 0)
    proxy_port = proxy.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
        await writer.drain()
        status = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=1)
        assert b"200 Connection Established" in status
        writer.write(tls_client_hello)
        await writer.drain()
        response = await asyncio.wait_for(reader.readexactly(len(b"FAST_SERVER_HELLO")), timeout=1)
        assert response == b"FAST_SERVER_HELLO"
        host_stats = store.state["domains"]["example.test"]
        assert any(item["outcome"] == "failure" for item in host_stats["direct"])
        assert any(item["outcome"] == "success" for item in host_stats["vps"])
    finally:
        writer.close()
        await writer.wait_closed()
        proxy.close()
        slow.close()
        fast.close()
        await proxy.wait_closed()
        await slow.wait_closed()
        await fast.wait_closed()
