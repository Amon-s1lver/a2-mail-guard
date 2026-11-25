"""Loopback-only transport for the mock email tool."""

import json
import secrets
import sqlite3
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


@contextmanager
def serve(service, principals, *, drop_reply=None, route="/send", execute=None):
    tokens = {principal: secrets.token_urlsafe(32) for principal in principals}
    identities = {f"Bearer {token}": principal for principal, token in tokens.items()}
    execute = service.send if execute is None else execute

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != route:
                self.reply(404, {"status": "unknown_endpoint"})
                return
            authorization = self.headers.get_all("Authorization", [])
            principal = identities.get(authorization[0]) if len(authorization) == 1 else None
            if principal is None:
                self.reply(401, {"status": "unauthenticated"})
                return
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                    raise ValueError("unsupported framing")
                size = int(lengths[0])
                if not 0 < size <= 24_000 or self.headers.get_content_type() != "application/json":
                    raise ValueError("invalid body")
                self.connection.settimeout(2)
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError("incomplete body")
                payload = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            except (ValueError, RecursionError, TimeoutError):
                self.reply(400, {"status": "invalid_json"})
                return

            try:
                status, result = execute(principal, payload)
            except sqlite3.Error:
                self.reply(503, {"status": "service_unavailable"})
                return
            if status == 201 and drop_reply is not None and drop_reply(principal, payload):
                # A fault injector controlled by the harness drops a committed reply.
                self.close_connection = True
                return
            self.reply(status, result)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", tokens
        finally:
            server.shutdown()
            thread.join()


def send_http(base_url, token, payload, *, route="/send"):
    request = Request(
        base_url + route,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(request, timeout=4) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        with error:
            return error.code, json.load(error)
