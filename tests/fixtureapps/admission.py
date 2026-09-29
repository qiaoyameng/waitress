"""Fixture application used to test the request admission callback."""

# Every request that reaches the WSGI application is recorded here so the
# response it produces can be told apart from an admission rejection.
calls = []


def app(environ, start_response):  # pragma: no cover
    calls.append(environ["PATH_INFO"])
    body = b"admission fixture app reached"
    start_response(
        "200 OK",
        [
            ("Content-Length", str(len(body))),
            ("Content-Type", "text/plain"),
        ],
    )
    return [body]


def admission_callback(method, target, headers):  # pragma: no cover
    # Rejects requests carrying an "X-Quota: exceeded" header, admits
    # everything else.
    if headers.get("X_QUOTA") == "exceeded":
        return (
            "403 Forbidden",
            [("Content-Type", "text/plain")],
            b"quota exceeded",
        )
    return None
