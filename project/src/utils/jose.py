# JSON Object Signing and Encryption (JOSE) functionality.

from typing import Any
import json

# ACME server implements the "ES256" signature algorithm (ECDSA using P-256 and SHA-256)
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

# ACME client's valid P-256 public key
key = ECC.generate(curve="P-256")

CERT_PATH = "cert.pem"
CERT_KEY_PATH = "cert_key.pem"


# Remove whitespace and line-breaks in the json dump that should be encoded (ibid).
# If the request should contain the empty payload "", then the request JSON would have to include a base64url encoding of "" under the payload key, not "".

from utils.encoding import base64_url_encode, base64_url_encode_bytes


class JSON_Web_Key:
    """
    A JSON data structure that represents a cryptographic key.
    The members of the object represent properties of the key, including its value.
    """

    def __init__(self, x: str, y: str):
        # Note: the members are ordered lexicographically by the Unicode [UNICODE] code points of their names.
        # "curve", the elliptic curve used with the key
        self.crv: str = "P-256"
        # "key type", the cryptographic algo family used with the key
        self.kty: str = "EC"
        self.x: str = x
        self.y: str = y

    def to_json(self) -> str:
        """Converts the JWK to a JSON-formatted string

        Returns:
            str: JSON-formatted string representing the JWK
        """
        return json.dumps(obj=self.__dict__)

    def to_b64json(self) -> str:
        return base64_url_encode(self.to_json())

    def get_thumbprint(self) -> bytes:
        """Computes the thumbprint of the JWK.
        https://datatracker.ietf.org/doc/html/rfc7638#section-3

        Returns:
            bytes: The thumbprint of the JWK
        """
        # 1. Converts the JWK into a JSON-formatted string without any whitespace characters (spaces or line breaks)
        # a comma ',' should be used to separate items in arrays or objects,
        # and a colon ':' should be used to separate keys and values, without any additional whitespace.
        jwk_json = json.dumps(obj=self.__dict__, separators=(",", ":"), sort_keys=True)

        # 2. Hash the octets of the UTF-8 representation of this JSON object with a cryptographic hash function H
        h = SHA256.new(jwk_json.encode("utf-8"))
        return h.digest()


# When using elliptic-curve signatures, use the concatenated byte representation of the r and s
# values as the signature
# (the signature output by the cryptographic library is not necessarily in the right format),
# as stated in Appendix A.3 of RFC7515.


def get_jwk():
    """Gets the JSON Web Key representation of the client's public key

    Returns:
        _type_: _description_
    """
    generated_key = key
    return JSON_Web_Key(
        base64_url_encode_bytes(generated_key.pointQ.x.to_bytes()),  # type: ignore
        base64_url_encode_bytes(generated_key.pointQ.y.to_bytes()),
    )  # type: ignore


class JWS_Protected_Header:
    """
    JSON object that contains the Header Parameters that are integrity protected by the JWS Signature digital signature or MAC operation.
    For the JWS Compact Serialization, this comprises the entire JOSE Header.
    For the JWS JSON Serialization, this is one component of the JOSE Header.


    6.5 Replay Protection
    Every JWS sent by an ACME client MUST include, in its protected header, the "nonce" header parameter, with contents as defined in Section 6.5.2.
    """

    def __init__(
        self,
        nonce: str,  # enables the verifier of a JWS to recognize when the same JWS has been submitted multiple times (replay attack)
        url: str,  # The URL to which the JWS object is directed
        jwk: JSON_Web_Key
        | None = None,  # JSON Web Key, the public key used that corresponds to the key used to digitally sign the JWS
        kid: str
        | None = None,  # Key ID, a hint indicating which key was used to secure the JWS.  This parameter allows originators to explicitly signal a change of key to recipients.
    ):
        self.alg = "ES256"  # ECDSA using P-256 and SHA-256. ECDSA signatures change each time based on the nonce used
        self.nonce: str = nonce
        self.url: str = url

        # jwk and kid are mutually exclusive
        if jwk:
            self.jwk: dict[str, Any] = jwk.__dict__
        else:
            self.kid: str | None = kid  # will be the account url once obtained

    def to_json(self) -> str:
        """Converts the object to a JSON string

        Returns:
            str: JSON-formatted string representing the object's attributes
        """
        content = self.__dict__
        return json.dumps(content)

    def to_b64json(self) -> str:
        """Converts the object to a base64url-encoded JSON string

        Returns:
            str: base64url-encoded JSON-formatted string representing the object's attributes
        """
        return base64_url_encode(self.to_json())


class JWS_Payload:
    """ """

    def __init__(self, content: dict[str, Any] | None = {}):
        self.payload: dict[str, Any] | None = content

    def to_json(self) -> str:
        """Converts the JWS payload to a JSON string

        Returns:
            str: JSON-formatted string representing the JWS payload
        """
        return json.dumps(self.payload)

    def to_b64json(self) -> str:
        """Base64url-encodes the JWS payload

        Returns:
            str: The base64url-encoded string
        """
        if (self.payload is not None) or (self.payload == {}):
            return base64_url_encode(self.to_json())
        else:
            return ""


class JWS_Signature:
    """JSON Web Signature. Represents digitally signed or MACed content using JSON data structures and base64url encoding.

    Arguments:
        protected_header {JWS_Protected_Header} -- [description]
        payload {JWS_Payload} -- [description]
    """

    def __init__(self, protected_header: JWS_Protected_Header, payload: JWS_Payload):
        message = protected_header.to_b64json() + "." + payload.to_b64json()
        h = SHA256.new(message.encode("utf-8"))
        signer = DSS.new(key, "fips-186-3")
        self.signature = signer.sign(h)

    def to_b64json(self) -> str:
        return base64_url_encode_bytes(self.signature)


def dns_challenge_rdata(key_authorization: str) -> str:
    """_summary_

    Args:
        key_authorization (_type_): _description_

    Returns:
        _type_: _description_
    """
    h = SHA256.new(key_authorization.encode("utf-8"))
    return base64_url_encode_bytes(h.digest())


if __name__ == "__main__":
    pass
