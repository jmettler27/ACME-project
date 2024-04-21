import click
import argparse

import threading
from time import sleep

from utils.jose import get_jwk, dns_challenge_rdata
from utils.encoding import base64_url_encode, base64_url_encode_bytes

from components.acme_client import ACME_Client
from components.dns_server import ACME_DNS_Server, make_dns_zone
from components.challenge_http_server import start_challenge_http_server
from components.cert_https_server import start_cert_https_server
from components.shutdown_http_server import start_shutdown_http_server


CHALLENGE_TYPE_DICT = {"dns01": "dns-01", "http01": "http-01"}

TITLE_NUMBER_OF_STARS = 25


@click.command()
# Positional arguments
@click.argument(
    "challenge_type",
    type=click.Choice(["dns01", "http01"]),
    nargs=1,
)
# Keyword arguments
@click.option(
    "--dir",
    required=True,
    type=str,
    help="The directory URL of the ACME server that should be used.",
)
@click.option(
    "--record",
    required=True,
    type=str,
    help="The IPv4 address which must be returned by your DNS server for all A-record queries.",
)
@click.option(
    "--domain",
    required=True,
    multiple=True,
    type=str,
    help="The domain for which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net.",
)
@click.option(
    "--revoke",
    is_flag=True,
    help="If present, immediately revoke the certificate after obtaining it.",
)
def main(challenge_type, dir, record, domain, revoke):
    """
    challenge_type: {dns01 | http01} Indicates which ACME challenge type the client should perform. Valid options are dns01 and http01 for the dns-01 and http-01 challenges, respectively.

    **Example:**
    Consider the following invocation of `run`:
    ```
    run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain netsec.ethz.ch --domain syssec.ethz.ch
    ```
    When invoked like this, your application should obtain a single certificate valid for both `netsec.ethz.ch` and `syssec.ethz.ch`. It should use the ACME server at the URL `https://example.com/dir` and perform the `dns-01` challenge. The DNS server of the application should respond with `1.2.3.4` to all requests for `A` records. Once the certificate has been obtained, your application should start its certificate HTTPS server and install the obtained certificate in this server.
    """

    # https://example.com/dir -> https://example.com/
    acme_serv_dir_url = dir.strip("dir")

    domains = domain
    dns_record_address = record

    print(
        f"""# General information: 
        * Challenge type: {challenge_type}
        * ACME server directory URL: {acme_serv_dir_url}
        * DNS record address: {dns_record_address}
        * Domains requested: {domains}
        * Revoke certificate? {"YES" if revoke else "NO"} 
        """
    )

    # ============================ Phase 1: Account creation ==============================
    print(
        ("*" * TITLE_NUMBER_OF_STARS)
        + " Phase 1: Account creation "
        + ("*" * TITLE_NUMBER_OF_STARS)
    )

    client = ACME_Client(serv_dir_url=acme_serv_dir_url)

    # Get the directory
    response = client.get_directory()
    if response.status_code != 200:
        print("[!] Error getting directory")
        return

    # ============================ Phase 2: Certificate issuance ==============================
    print(
        ("*" * TITLE_NUMBER_OF_STARS)
        + " Phase 2: Certificate issuance "
        + ("*" * TITLE_NUMBER_OF_STARS)
    )

    # Submit order
    response = client.submit_order(domains=domains)
    if response.status_code != 201:
        print("[!] Error submitting order")
        return

    authorization_urls = response.json()["authorizations"]
    finalize_url = response.json()["finalize"]
    print("[\u2713] Authorization URLs:")
    for url in authorization_urls:
        print(f"\t- {url}")
    print("[\u2713] Finalize URL:", finalize_url)

    # 2. Prove control of any identifiers requested in the certificate
    # Fetch challenges
    print("# Fetching challenges...")

    http_challenge_urls: list[str] = []
    http_tokens_and_kAs: dict[str, str] = {}

    dns_challenge_urls: list[str] = []
    dns_ids_and_rdata: list[tuple[str, str]] = []

    jwk_thumbprint: bytes = get_jwk().get_thumbprint()

    for authorization_url in authorization_urls:
        ## Get authorization object (7.1.4. Authorization Objects)
        print(f"# Getting authorization object at {authorization_url}...")
        response = client.post_as_get_request(url=authorization_url)
        if response.status_code != 200:
            print("-> Error fetching authorization object")
            return

        # if challenge_type == "dns01":
        # The identifier that the account is authorized to represent
        identifier = response.json()["identifier"]["value"]
        print(f"[\u2713] The account is authorized to represent {identifier}")

        ## Get challenge objects (7.1.5. Challenge Objects)
        challenges = response.json()["challenges"]
        # print("[\u2713] Challenges:", challenges)

        for chall in challenges:
            # Challenge type
            chall_type = chall["type"]
            # if chall_type != CHALLENGE_TYPE_DICT[challenge_type]:
            #     continue

            # Challenge URL, token, and key authorization (# 8.1 Key Authorizations)
            chall_url: str = chall["url"]
            chall_token: str = chall["token"]
            chall_kA: str = chall_token + "." + base64_url_encode_bytes(jwk_thumbprint)

            if chall_type == "http-01":
                http_challenge_urls.append(chall_url)
                http_tokens_and_kAs[chall_token] = chall_kA

            if chall_type == "dns-01":
                dns_challenge_urls.append(chall_url)
                # Important: there may not be a 1:1 mapping
                dns_ids_and_rdata.append((identifier, dns_challenge_rdata(chall_kA)))

    print("[*] HTTP Challenge URLs:")
    for url in http_challenge_urls:
        print(f"\t- {url}")

    print("[*] HTTP Tokens and key authorizations:")
    for key, value in http_tokens_and_kAs.items():
        print(f"\t- {key}: {value}")

    print("[*] DNS Challenge URLs:")
    for url in dns_challenge_urls:
        print(f"\t- {url}")

    print("[*] DNS Identifiers and TXT record data: ")
    for identifier, rdata in dns_ids_and_rdata:
        print(f"\t- {identifier}: {rdata}")

    dns_zone = make_dns_zone(
        domains=domain,
        address=dns_record_address,
        domains_and_rdata=dns_ids_and_rdata,
    )
    print(f"[*] DNS Zone: \n{dns_zone}")

    dns_server = ACME_DNS_Server(dns_zone=dns_zone)
    dns_server.start()

    sleep(10)

    # Respond to challenges
    challenge_validated = False
    ## HTTP Challenges
    if challenge_type == "http01":
        challenge_server_thread = threading.Thread(
            target=start_challenge_http_server, args=([http_tokens_and_kAs])
        )
        challenge_server_thread.start()

        sleep(5)

        challenge_validated = client.http_challenges(
            tokens_http=http_tokens_and_kAs,
            challenge_urls=http_challenge_urls,
        )

    ## DNS Challenges
    if challenge_type == "dns01":
        # Respond to challenges
        challenge_validated = client.dns_challenges(challenge_urls=dns_challenge_urls)
        # print(res)

    if not challenge_validated:
        print("[!] Error responding to challenges")
        dns_server.stop()

        # exit program
        if challenge_type == "http01":
            challenge_server_thread.join()
        return False

    # 3. Finalize the order by submitting a CSR
    # Finalize order
    cert_downloaded = client.finalize_order(domains=domains, finalize_url=finalize_url)
    if not cert_downloaded:
        print("[!] Error finalizing order")
        dns_server.stop()

        # exit program
        if challenge_type == "http01":
            challenge_server_thread.join()
        return False

    # Poll for status

    # Download certificate

    if revoke:
        client.revoke_cert()

    cert_https_server_thread = threading.Thread(target=start_cert_https_server)
    cert_https_server_thread.start()
    # start_cert_https_server()

    shutdown_server_thread = threading.Thread(target=start_shutdown_http_server)
    shutdown_server_thread.start()
    # start_shutdown_http_server()

    cert_https_server_thread.join()
    shutdown_server_thread.join()


if __name__ == "__main__":
    main()
