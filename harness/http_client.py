"""
Rate-limited HTTP client with logging.
Every request is logged for evidence/PoC reproduction.
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests


@dataclass
class RequestLog:
    method: str
    url: str
    status: int
    request_headers: dict
    response_headers: dict
    body: str
    response_body: str
    duration_ms: float
    timestamp: str


class HttpClient:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        if config.proxy:
            self.session.proxies = {"http": config.proxy, "https": config.proxy}
        self.log: list[RequestLog] = []
        self._last_request = 0.0

    def get(self, path: str, headers: dict | None = None, **kwargs) -> requests.Response:
        return self._request("GET", path, headers=headers, **kwargs)

    def post(self, path: str, headers: dict | None = None, **kwargs) -> requests.Response:
        return self._request("POST", path, headers=headers, **kwargs)

    def put(self, path: str, headers: dict | None = None, **kwargs) -> requests.Response:
        return self._request("PUT", path, headers=headers, **kwargs)

    def delete(self, path: str, headers: dict | None = None, **kwargs) -> requests.Response:
        return self._request("DELETE", path, headers=headers, **kwargs)

    def patch(self, path: str, headers: dict | None = None, **kwargs) -> requests.Response:
        return self._request("PATCH", path, headers=headers, **kwargs)

    def _request(self, method: str, path: str, headers: dict | None = None, **kwargs) -> requests.Response:
        self._rate_limit()
        url = urljoin(self.config.base_url, path)
        merged_headers = {**self.config.no_auth_headers(), **(headers or {})}

        start = time.monotonic()
        try:
            resp = self.session.request(
                method, url, headers=merged_headers,
                timeout=self.config.timeout, **kwargs,
            )
        except requests.RequestException as e:
            self._log_error(method, url, merged_headers, str(e))
            raise

        duration = (time.monotonic() - start) * 1000
        self._log_request(method, url, merged_headers, resp, duration, kwargs)
        return resp

    def _rate_limit(self):
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.config.rate_limit:
            time.sleep(self.config.rate_limit - elapsed)
        self._last_request = time.monotonic()

    def _log_request(self, method, url, req_headers, resp, duration, kwargs):
        body = ""
        if "json" in kwargs:
            body = json.dumps(kwargs["json"])
        elif "data" in kwargs:
            body = str(kwargs["data"])

        try:
            resp_body = resp.text[:5000]
        except Exception:
            resp_body = "<binary>"

        entry = RequestLog(
            method=method, url=url, status=resp.status_code,
            request_headers=req_headers, response_headers=dict(resp.headers),
            body=body, response_body=resp_body, duration_ms=round(duration, 1),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self.log.append(entry)

    def _log_error(self, method, url, headers, error):
        entry = RequestLog(
            method=method, url=url, status=0,
            request_headers=headers, response_headers={},
            body="", response_body=f"ERROR: {error}", duration_ms=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self.log.append(entry)

    def save_log(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        entries = []
        for entry in self.log:
            entries.append({
                "method": entry.method, "url": entry.url, "status": entry.status,
                "request_headers": entry.request_headers,
                "response_headers": entry.response_headers,
                "body": entry.body, "response_body": entry.response_body[:1000],
                "duration_ms": entry.duration_ms, "timestamp": entry.timestamp,
            })
        path.write_text(json.dumps(entries, indent=2))
