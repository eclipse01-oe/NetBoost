import asyncio

import pytest

from app.vps.main import handle


@pytest.mark.asyncio
async def test_vps_health_probe_returns_200_without_opening_a_tunnel():
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /health HTTP/1.1\r\nHost: netboost.local\r\nConnection: close\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=1)
        assert response.startswith(b"HTTP/1.1 200 OK")
        assert b"NetBoost VPS relay ready" in response
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
