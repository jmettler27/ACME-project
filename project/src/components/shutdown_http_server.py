# An HTTP server to receive a shutdown signal.

from flask import Flask
import os, signal

app = Flask(__name__)

PORT = 5003
IP_ADDRESS = "0.0.0.0"


@app.route("/shutdown", methods=["GET"])
def shutdown():
    """Terminate the application.

    Once testing is complete, the testing environment will issue a GET /shutdown request to this server.
    """
    print("[*] SHUTDOWN HTTP SERVER: received a shutdown request")
    os.kill(os.getpid(), signal.SIGTERM)


def start_shutdown_http_server():
    print("[*] Starting shutdown HTTP server...")

    app.run(host=IP_ADDRESS, port=PORT, debug=True, use_reloader=False)


# if __name__ == "__main__":
#     start_shutdown_http_server()
