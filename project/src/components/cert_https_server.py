# An HTTPS server which uses a certificate obtained by the ACME client.

from flask import Flask

app = Flask(__name__)

PORT = 5001
IP_ADDRESS = "0.0.0.0"

from utils.jose import CERT_PATH, CERT_KEY_PATH


@app.route("/", methods=["GET"])
def index():
    print("[*] CERT HTTPS SERVER: received a GET / request")
    # The testing environment will issue a GET / request to this server in order to obtain the certificate served by this server.
    return "I am the certificate HTTPS server"


def start_cert_https_server():
    print("[*] Starting certificate HTTPS server...")

    # Use the newly obtained certificate
    # The server should serve the full certificate chain obtained from the ACME server, i.e., including the intermediate certificate.
    app.run(host=IP_ADDRESS, port=PORT, ssl_context=(CERT_PATH, CERT_KEY_PATH))
