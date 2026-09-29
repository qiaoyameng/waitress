def app(environ, start_response):  # pragma: no cover
    """WSGI app that proves it was reached by returning a marker body."""
    body = b"application reached"
    start_response(
        "200 OK",
        [
            ("Content-Length", str(len(body))),
            ("Content-Type", "text/plain"),
        ],
    )
    return [body]


def reject_quota_exceeded(request):  # pragma: no cover
    """Admission callback rejecting requests that carry X-Quota: exceeded."""
    if request.headers.get("X_QUOTA") == "exceeded":
        return (
            "403 Forbidden",
            [("Content-Type", "text/plain")],
            b"quota exceeded",
        )

    return None
