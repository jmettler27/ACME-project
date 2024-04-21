# An HTTP server to respond to http-01 queries of the ACME server.

from flask import Flask, abort
from flask.wrappers import Response


app = Flask(__name__)

# The TCP port to which the ACME server will direct all http-01 challenges. Deviates from RFC8555 (8.3 HTTP Challenge).
PORT = 5002

IP_ADDRESS = "0.0.0.0"

# Tokens and key_authorization values for the http-01 challenge
http_tokens_and_kAs: dict[str, str] = {}


@app.route("/.well-known/acme-challenge/<string:token>", methods=["GET"])
def challenge(token: str):
    """Respond to http-01 challenge

    Args:
        token (str): The token provided by the ACME server

    Returns:
        str: The response to the challenge
    """
    print("HTTP CHALLENGE SERVER: received a request")

    if token not in http_tokens_and_kAs:
        abort(404, "Unknown token")
    else:
        return Response(
            response=http_tokens_and_kAs[token],
            headers={"Content-Type": "application/octet-stream"},
        )


def start_challenge_http_server(tokens_and_kAs: dict[str, str]):
    print("Starting challenge HTTP server...")
    http_tokens_and_kAs.update(tokens_and_kAs)
    # print(f"HTTP Tokens and Key authorizations: {http_tokens_and_kAs}")
    app.run(host=IP_ADDRESS, port=PORT, debug=True, use_reloader=False)
