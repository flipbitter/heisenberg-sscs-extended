"""Small, bounded HTTPS transport for the existing collectors and the URL controller"""

import http.client
import ipaddress
import json
import os
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urljoin

HOSTS = frozenset(
    {
        "api.deps.dev",
        "api.github.com",
        "pypi.org",
        "registry.npmjs.org",
        "crates.io",
        "static.crates.io",
    }
)

EVENTS = []


def public_addresses(host):
    records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys([r[4][0] for r in records]))
    if not addresses:
        raise ValueError(f"Could not resolve {host}")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global or ip.is_multicast or getattr(ip, "ipv4_mapped", None):
            raise ValueError("Non-public DNS anser rejected")
    return addresses


def validate_url(url, hosts):
    if any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise ValueError("Control characters, whitespace, and backslashes rejected")
    p = urlsplit(url)
    if (
        p.scheme != "https"
        or p.hostname not in hosts
        or p.port not in (None, 443)
        or p.username is not None
        or p.password is not None
        or p.fragment
    ):
        raise ValueError(
            "URL must be HTTPS on an explicitly allowed host, port 443, without userinfo/fragment"
        )
    return p


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


@dataclass
class Response:
    status_code: int
    content: bytes
    headers: dict
    url: str

    @property
    def text(self):
        return self.content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.content)

    def raise_for_status(self):
        if not 200 <= self.status_code < 300:
            raise ValueError(
                f"HTTP {self.status_code} from {urlsplit(self.url).hostname}"
            )


def get(
    url,
    headers=None,
    timeout=15,
    allow_redirects=True,
    *,
    hosts=HOSTS,
    max_bytes=None,
    deadline_seconds=35,
):
    """Compatible get surface used by the inspected collectors. DNS also has an
    outer worker/controller wall-clock watchdog, since libc DNS can block.
    """
    if max_bytes is None:
        max_bytes = int(os.environ.get("HEISENBERG_MAX_HTTP_BYTES", 64 * 1024 * 1024))
    if max_bytes < 1:
        raise ValueError("HTTP byte budget must be positive")
    deadline = time.monotonic() + deadline_seconds
    base_headers = {}
    for key, value in (headers or {}).items():
        if key.lower() not in {
            "authorization",
            "accept",
            "x-github-api-version",
            "user-agent",
        }:
            raise ValueError("Unsupported outbound header")
        if (
            key.lower() == "authorization"
            and urlsplit(url).hostname != "api.github.com"
        ):
            raise ValueError("Credentials only allowed on the fixed GitHub API host")
        base_headers[key] = value
    try:
        for hop in range(4):
            p = validate_url(url, hosts)
            address = public_addresses(p.hostname)[0]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP total deadline exceeded")
            connection = PinnedHTTPS(p.hostname, address, min(15, remaining))
            try:
                connection.putrequest(
                    "GET",
                    (p.path or "/") + ("?" + p.query if p.query else ""),
                    skip_accept_encoding=True,
                )
                for key, value in base_headers.items():
                    connection.putheader(key, value)
                connection.endheaders()
                reply = connection.getresponse()
                h = {k.lower(): v for k, v in reply.getheaders()}
                EVENTS.append(
                    {"host": p.hostname, "path": p.path, "status": reply.status}
                )
                if reply.status in {301, 302, 303, 307, 308}:
                    if not allow_redirects or hop == 3 or "location" not in h:
                        raise ValueError("Redirect denied or redirect budget exhausted")
                    new_url = urljoin(url, h["location"])
                    validate_url(new_url, hosts)
                    # Never forward credentials across any redirect, even within a host.
                    base_headers = {
                        k: v
                        for k, v in base_headers.items()
                        if k.lower() != "authorization"
                    }
                    url = new_url
                    continue
                if h.get("content-encoding", "identity").lower() != "identity":
                    raise ValueError("Compressed HTTP bodies are not accepted")
                if int(h.get("content-length", "0")) > max_bytes:
                    raise ValueError("HTTP response exceeds byte budget")
                chunks, size = [], 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("HTTP total deadline exceeded")
                    (
                        connection.sock.settimeout(min(10, remaining))
                        if connection.sock
                        else None
                    )
                    chunk = reply.read1(min(65536, max_bytes + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError("HTTP response exceeds byte budget")
                    chunks.append(chunk)
                return Response(reply.status, b"".join(chunks), h, url)
            finally:
                connection.close()
        raise ValueError("Redirect budget exhausted")
    except Exception as exc:
        EVENTS.append({"host": urlsplit(url).hostname, "error": type(exc).__name__})
        raise
