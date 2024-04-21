from base64 import urlsafe_b64encode


def base64_url_encode(data: any) -> str:
    """Encodes the given data using the url-safe base64 encoding with trailing '=' removed (as per Section 2 of RFC 7515) https://datatracker.ietf.org/doc/html/rfc7515#autoid-3

    Args:
        data (any): The data to be encoded

    Returns:
        str: The base64url-encoded string
    """
    return urlsafe_b64encode(data.encode("utf-8")).rstrip(b"=").decode("utf-8")


def base64_url_encode_bytes(data: bytes) -> str:
    """Base64url-encodes the given data bytes

    Args:
        data (bytes): The data to be encoded

    Returns:
        str: The base64url-encoded string
    """
    return urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


if __name__ == "__main__":
    pass
