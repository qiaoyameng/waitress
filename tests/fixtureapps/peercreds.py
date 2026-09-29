import json


def app(environ, start_response):  # pragma: no cover
    creds = environ.get("waitress.peer_credentials")
    if creds is None:
        meta = None
    else:
        meta = {"pid": creds.pid, "uid": creds.uid, "gid": creds.gid}
    response = json.dumps(meta).encode("utf8")
    start_response(
        "200 OK",
        [
            ("Content-Length", str(len(response))),
            ("Content-Type", "application/json"),
        ],
    )
    return [response]
