from app.routing.proxy import _host_port, _prepare_http_request
from app.vps.main import is_disallowed_literal, parse_connect


def test_absolute_http_request_is_rewritten_to_origin_form():
    header = (b"GET http://example.com/news?x=1 HTTP/1.1\r\n"
              b"Host: example.com\r\nProxy-Connection: keep-alive\r\n\r\n")
    host, port, outgoing, safe_retry, method = _prepare_http_request(header)
    assert (host, port) == ("example.com", 80)
    assert outgoing.startswith(b"GET /news?x=1 HTTP/1.1\r\n")
    assert b"Proxy-Connection" not in outgoing
    assert b"Connection: close" in outgoing
    assert safe_retry is True
    assert method == "GET"


def test_body_bearing_post_is_not_marked_safe_to_retry():
    header = (b"POST http://example.com/submit HTTP/1.1\r\n"
              b"Host: example.com\r\nContent-Length: 3\r\n\r\n")
    _host, _port, _outgoing, safe_retry, method = _prepare_http_request(header)
    assert method == "POST"
    assert safe_retry is False


def test_connect_authorities():
    assert _host_port("example.com:443", 443) == ("example.com", 443)
    assert parse_connect(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n") == ("example.com", 443)


def test_vps_rejects_local_destination_literals():
    assert is_disallowed_literal("127.0.0.1") is True
    assert is_disallowed_literal("10.0.0.2") is True
    assert is_disallowed_literal("1.1.1.1") is False


def test_tls_replay_guard_only_allows_single_initial_client_hello_record():
    from app.routing.proxy import _safe_tls_client_hello_replay

    body = b"\x01CLIENT_HELLO"
    record = b"\x16\x03\x01" + len(body).to_bytes(2, "big") + body
    assert _safe_tls_client_hello_replay(record) == record
    assert _safe_tls_client_hello_replay(record + b"\x17\x03\x03\x00\x03xyz") is None
    assert _safe_tls_client_hello_replay(b"not-tls") is None
