# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# core/middleware.py
#
# Middleware for defensive request bounds checking (e.g., query string size).
#
# OWASP touchpoints:
#   - A01: Broken Access Control (indirect)
#       * Not an auth control, but helps enforce "least abuse" on endpoints
#         that might otherwise be hammered with giant query strings.
#   - A05: Security Misconfiguration
#       * Avoids letting unbounded querystrings flow into the rest of the stack.
#   - A08: Software and Data Integrity Failures
#       * Defensive parsing avoids over-allocating on attacker-controlled input.

from __future__ import annotations

from typing import Callable
from urllib.parse import parse_qsl

from django.http import HttpResponse
from django.http import HttpResponseBadRequest


class QueryStringSizeLimitMiddleware:
    """
    Reject requests whose query string is unreasonably large.

    Limits:
      - MAX_TOTAL_LEN: max number of characters in the raw query string.
      - MAX_PARAM_LEN: max length of any single parameter value.
      - MAX_PARAM_COUNT: max number of parameters.

    If any of these are exceeded, we return HTTP 414 (URI Too Long) with a
    generic message and do NOT call the downstream view.

    This is primarily a hardening measure against:
      - pathologically long ?noise=... style payloads
      - naive parsers accidentally allocating huge buffers
    """

    # Tune these for your app; these are pretty generous defaults.
    MAX_TOTAL_LEN = 4096          # total characters in QUERY_STRING
    MAX_PARAM_LEN = 1024          # max length of any single value
    MAX_PARAM_COUNT = 100         # max distinct key/value pairs

    def __init__(self, get_response: Callable):
        self.get_response = get_response

    def __call__(self, request):
        qs = request.META.get("QUERY_STRING", "") or ""

        # Fast path: empty or tiny query string
        if not qs:
            return self.get_response(request)

        # 1) Cap on overall query string length
        if len(qs) > self.MAX_TOTAL_LEN:
            return self._too_long_response()

        # 2) Optional deeper inspection: parameter count and per-param length
        try:
            params = parse_qsl(qs, keep_blank_values=True, max_num_fields=self.MAX_PARAM_COUNT + 1)
        except ValueError:
            # parse_qsl can raise if max_num_fields is exceeded or malformed input
            return self._too_long_response()

        # Too many params?
        if len(params) > self.MAX_PARAM_COUNT:
            return self._too_long_response()

        # Any value too large?
        for key, value in params:
            if len(value) > self.MAX_PARAM_LEN:
                return self._too_long_response()

        # If all checks pass, let the request proceed
        return self.get_response(request)

    @staticmethod
    def _too_long_response() -> HttpResponse:
        # Use 414 (URI Too Long) to be explicit; you could also return 400.
        return HttpResponse(
            "Request URI too long.",
            status=414,
            content_type="text/plain; charset=utf-8",
        )

MAX_QS_LENGTH = 2048   # or whatever threshold you want

class QueryStringLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw_qs = request.META.get("QUERY_STRING", "")
        if len(raw_qs) > MAX_QS_LENGTH:
            return HttpResponseBadRequest("Query string too long.")
        return self.get_response(request)

# src/core/middleware/bodycap.py
from django.http import HttpResponse

class BodySizeLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.max_bytes = 3 * 1024 * 1024  # 3 MB

    def __call__(self, request):
        length = request.META.get("CONTENT_LENGTH")
        try:
            length_int = int(length) if length is not None else 0
        except ValueError:
            length_int = 0

        if length_int > self.max_bytes:
            return HttpResponse(
                "Request body too large",
                status=413,
                content_type="text/plain",
            )

        return self.get_response(request)
