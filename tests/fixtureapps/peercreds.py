import json


def app(environ, start_response):  # pragma: no cover
    body = json.dumps(
        {
            "waitress.unix_peer_pid": environ.get("waitress.unix_peer_pid"),
            "waitress.unix_peer_uid": environ.get("waitress.unix_peer_uid"),
            "waitress.unix_peer_gid": environ.get("waitress.unix_peer_gid"),
            "http_x_peer_uid": environ.get("HTTP_X_PEER_UID"),
        }
    ).encode("utf8")
    start_response(
        "200 OK",
        [
            ("Content-Length", str(len(body))),
            ("Content-Type", "application/json"),
        ],
    )
    return [body]
