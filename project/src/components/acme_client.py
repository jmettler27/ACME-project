import json, requests
from pathlib import Path
from time import sleep

from utils.jose import (
    JWS_Protected_Header,
    JWS_Payload,
    JWS_Signature,
    get_jwk,
    CERT_PATH,
    CERT_KEY_PATH,
)
from utils.encoding import base64_url_encode_bytes


PEBBLE_CERT_PATH = Path(__file__).parent.parent.parent / "pebble.minica.pem"
DIRECTORY = "dir"  # "directory" resource

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class ACME_Client:
    """ACME client.

    Args:
        serv_dir_url (str): URL of the ACME server's directory object
    """

    def __init__(self, serv_dir_url) -> None:
        self.serv_dir_url: str = serv_dir_url
        self.session: requests.Session = requests.Session()
        self.resource_urls: dict[str, str] = {}
        self.received_nonces: list[str] = []
        self.account_url: str | None = None
        # self.dns_server: My_DNS_Server = None  # type: ignore

    def get_request(self, url: str) -> requests.Response:
        """Make a GET request to the provided URL.

        Args:
            url (str): URL to make the request to

        Returns:
            requests.Response: Response object
        """
        return self.session.get(url, verify=PEBBLE_CERT_PATH)

    def head_request(self, url: str) -> requests.Response:
        """Make a HEAD request to the provided URL.

        Args:
            url (str): URL to make the request to

        Returns:
            requests.Response: Response object
        """
        return self.session.head(url, verify=PEBBLE_CERT_PATH)

    def generic_post_request(
        self, url: str, protected_header: JWS_Protected_Header, payload: JWS_Payload
    ) -> requests.Response:
        # Because client requests in ACME carry JWS objects in the Flattened JSON Serialization,
        # they must have the Content-Type header field set to "application/jose+json".
        headers = {"Content-Type": "application/jose+json"}

        signature: JWS_Signature = JWS_Signature(
            protected_header=protected_header, payload=payload
        )

        # Before sending a POST request to the server, an ACME client needs to
        # have a fresh anti-replay nonce to put in the "nonce" header of the JWS.
        # In most cases, the client will have gotten a nonce from a previous request.
        # However, the client might sometimes need to get a new nonce,
        # e.g., on its first request to the server or if an existing nonce is no longer valid.
        response: requests.Response = self.session.post(
            url=url,
            headers=headers,
            data=json.dumps(
                {
                    "protected": protected_header.to_b64json(),
                    "payload": payload.to_b64json(),
                    "signature": signature.to_b64json(),
                }
            ),
            verify=PEBBLE_CERT_PATH,
        )

        # 6.5 Replay Protection
        # An ACME server provides nonces to clients using the HTTP Replay-Nonce header field,
        # as specified in Section 6.5.1.
        # The server MUST include a Replay-Nonce header field in every successful response to a POST request
        # and SHOULD provide it in error responses as well.
        if "Replay-Nonce" in response.headers:
            self.received_nonces.append(response.headers["Replay-Nonce"])

        return response

    def post_request(
        self, url: str, protected_header: JWS_Protected_Header, payload: JWS_Payload
    ) -> requests.Response:
        """Make a POST request to the provided URL.

        Args:
            url (str): _description_
            protected_header (JWS_Protected_Header): _description_
            payload (JWS_Payload): _description_

        Returns:
            requests.Response: _description_
        """
        return self.generic_post_request(
            url=url, protected_header=protected_header, payload=payload
        )

    def post_as_get_request(self, url: str) -> requests.Response:
        """Make a POST-as-GET request to the provided URL.

        POST request whose JWS Payload is a zero-length octet string / the empty string ("").

        Args:
            url (str): _description_

        Returns:
            requests.Response: _description_
        """
        protected_header: JWS_Protected_Header = JWS_Protected_Header(
            nonce=self.get_nonce(),
            url=url,
            kid=self.account_url,
        )

        payload: JWS_Payload = JWS_Payload(None)

        return self.generic_post_request(
            url=url, protected_header=protected_header, payload=payload
        )

    def get_directory(self) -> requests.Response:
        """Get the directory object from the ACME server.

        7.1.1. Directory

        In order to help clients configure themselves with the right URLs for
        each ACME operation, ACME servers provide a directory object.  This
        should be the only URL needed to configure clients.  It is a JSON
        object, whose field names are drawn from the resource registry
        (Section 9.7.5) and whose values are the corresponding URLs.

        Returns:
            int: HTTP status code (200 if successful)
        """
        print("# Getting directory...")
        response = self.get_request(self.serv_dir_url + DIRECTORY)
        self.resource_urls = response.json()
        return response

    def get_nonce(self) -> str:
        """_summary_

        7.2 Getting a Nonce https://datatracker.ietf.org/doc/html/rfc8555#section-7.2


        Returns:
            str: _description_
        """
        # print("# Getting nonce...")
        if not (self.received_nonces):
            response = self.head_request(self.resource_urls["newNonce"])
            if "Replay-Nonce" in response.headers:
                nonce = response.headers["Replay-Nonce"]
                self.received_nonces.append(nonce)
        return self.received_nonces.pop()

    def create_account(self) -> str:
        """
        Create an account on the ACME server.

        Returns:
            str: The account URL (kid) received from the server
        """
        print("# Creating account...")
        request_url = self.resource_urls["newAccount"]

        protected_header: JWS_Protected_Header = JWS_Protected_Header(
            nonce=self.get_nonce(),
            url=request_url,
            jwk=get_jwk(),
        )

        content = {
            "termsOfServiceAgreed": True,
        }
        payload: JWS_Payload = JWS_Payload(content=content)

        response: requests.Response = self.post_request(
            url=request_url,
            protected_header=protected_header,
            payload=payload,
        )

        if response.status_code == 201 and "Location" in response.headers:
            self.account_url = response.headers["Location"]
            print(f"[\u2713] Account URL: {self.account_url}")

        return self.account_url

    def submit_order(self, domains: list[str]) -> requests.Response:
        """
        Create an order for the requested domains.
        """
        print("# Submitting order...")

        # Create an account if one doesn't exist -> kid=account URL, jwk=None
        if not self.account_url:
            self.create_account()

        # Submit an order for a certificate to be issued
        request_url = self.resource_urls["newOrder"]

        protected_header: JWS_Protected_Header = JWS_Protected_Header(
            nonce=self.get_nonce(),
            url=request_url,
            kid=self.account_url,
        )

        identifiers = [{"type": "dns", "value": domain} for domain in domains]
        content = {"identifiers": identifiers}
        payload: JWS_Payload = JWS_Payload(content=content)

        return self.post_request(
            url=request_url, protected_header=protected_header, payload=payload
        )

    def ready_for_challenge_validation(self, challenge_url) -> requests.Response:
        """
        Indicates to the ACME server that the client is ready for challenge validation.

        Args:
            challenge_url (_type_): _description_

        Returns:
            requests.Response: _description_
        """
        print(f"# Sending ready for challenge validation at {challenge_url}...")
        return self.post_request(
            url=challenge_url,
            protected_header=JWS_Protected_Header(
                nonce=self.get_nonce(),
                url=challenge_url,
                kid=self.account_url,
            ),
            payload=JWS_Payload(),  # empty JSON body {}
        )

    def poll_for_status(self, urls):
        # Poll for status

        print("# Polling for status...")

        for url in urls:
            print(f"\t - at {url}:")

            while True:
                response = self.post_as_get_request(url=url)
                status = response.json()["status"]
                if status == "pending":
                    print("\t [*] Pending...")
                if status == "valid":
                    print(f"\t [\u2713] Success: challenge at {url} is validated")
                    break
                if status == "invalid":
                    print("\t [!] Error:", response.json()["error"])
                    return False
                sleep(5)
        return True

    def http_challenges(self, tokens_http: dict[str, str], challenge_urls: list[str]):
        # Respond to HTTP challenges

        print("# Respond to HTTP challenges...")

        for url in challenge_urls:
            response = self.ready_for_challenge_validation(challenge_url=url)
            if response.status_code != 200:
                print("[!] Error readying for challenge validation")
                return False
            print(
                f"[\u2713] HTTP challenge ready at {url} (code {response.status_code})"
            )

        # Poll for status
        return self.poll_for_status(urls=challenge_urls)

    def dns_challenges(self, challenge_urls: list[str]):
        # Respond to DNS challenges

        print("# Respond to DNS challenges...")

        for url in challenge_urls:
            response = self.ready_for_challenge_validation(challenge_url=url)
            if response.status_code != 200:
                print("[!] Error readying for challenge validation")
                return False
            print(
                f"[\u2713] DNS challenge ready at {url} (code {response.status_code})"
            )

        # Poll for status
        return self.poll_for_status(urls=challenge_urls)

    def finalize_order(self, domains: str, finalize_url: str) -> requests.Response:
        # POST finalize url

        print("# Finalizing order...")

        # You can use any key type and key size supported by openSSL and Pebble for the requested certificate.

        # Use a proper byte encoding of the integer key parameters (e and n in RSA):
        # The resulting byte string of an integer i should be ceil( i.bit_length() / 8 ) bytes long.
        # In particular, there must be no leading zero octet in the bytestring (Section 8 of RFC 8555).

        # When using RSA, create the signature with PKCSv1.5 padding and the SHA256 hash function (as in Appendix A.2 of RFC7515)

        print("[*] Generating RSA private key...")
        # Generate the RSA private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Store the private key in a file

        with open(CERT_KEY_PATH, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        print("[*] Generating CSR...")
        # Generate a CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        # Provide various details about who we are.
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Zurich"),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ETHZ"),
                        # x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    # Describe what sites we want this certificate for.
                    [x509.DNSName(domain) for domain in domains]
                ),
                critical=False,
                # Sign the CSR with the private key.
            )
            .sign(key, hashes.SHA256())
        )

        # In the request, the CSR is sent in the base64url-encoded version of the DER format (RFC 8555).
        csr_der = csr.public_bytes(encoding=serialization.Encoding.DER)
        csr_der_b64 = base64_url_encode_bytes(csr_der)

        protected_header: JWS_Protected_Header = JWS_Protected_Header(
            nonce=self.get_nonce(),
            url=finalize_url,
            kid=self.account_url,
        )

        content = {"csr": csr_der_b64}
        payload: JWS_Payload = JWS_Payload(content=content)

        response = self.post_request(
            url=finalize_url, protected_header=protected_header, payload=payload
        )

        if response.status_code != 200:
            print("[!] Error finalizing order")
            return False

        order_url = response.headers["Location"]
        response = self.download_cert(order_url=order_url)

        return response

    def download_cert(self, order_url: str) -> requests.Response:
        # Poll for status

        print(f"# Polling for status... at {order_url}")

        while True:
            response = self.post_as_get_request(url=order_url)
            status = response.json()["status"]
            if status == "pending":
                print("\t [*] Pending...")
            if status == "valid":
                download_url = response.json()["certificate"]
                response = self.post_as_get_request(url=download_url)
                if response.status_code != 200:
                    print("[!] Error downloading certificate")
                    return False
                cert = response.content
                print("\t [\u2713] Success: certificate downloaded:\n", response.text)

                # Save certificate to file
                with open(CERT_PATH, "wb") as f:
                    f.write(cert)
                break
            if status == "invalid":
                print("\t [!] Error:", response.json()["error"])
                return False
            sleep(5)
        return True

    def revoke_cert(self):
        print("[#] Revoking certificate...")

        with open(CERT_PATH, "rb") as f:
            cert_bytes = f.read()

        # The certificate to be revoked is sent in the base64url-encoded version of the DER format (RFC 8555).
        cert = x509.load_pem_x509_certificate(
            data=cert_bytes, backend=default_backend()
        )
        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
        cert_der_b64 = base64_url_encode_bytes(cert_der)

        request_url = self.resource_urls["revokeCert"]
        response = self.post_request(
            url=request_url,
            protected_header=JWS_Protected_Header(
                nonce=self.get_nonce(),
                url=request_url,
                kid=self.account_url,
            ),
            payload=JWS_Payload(content={"certificate": cert_der_b64}),
        )

        if response.status_code != 200:
            print("[!] Error revoking certificate:", response.json())
            return False

        print("[\u2713] Certificate revoked")
        return True
