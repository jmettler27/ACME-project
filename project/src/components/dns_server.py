from dnslib import QTYPE, DNSRecord, textwrap, RR, A, TXT
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger
from dnslib.label import DNSLabel
from dnslib.zoneresolver import ZoneResolver

# The IP address to which the ACME server will direct all DNS queries.
IP_ADDRESS = "0.0.0.0"
# The UDP port to which the ACME server will direct all DNS queries.
PORT = 10053
# The prefix of the path to the TXT resource record that must be provisioned to the DNS server.
VALIDATION_PREFIX = "_acme-challenge."
# TTL defined in RFC 8555 (8.4 DNS Challenge)
TTL = 300


def make_dns_zone(
    domains: list[str], address: str, domains_and_rdata: list[tuple[str, str]]
) -> str:
    """
    Constructs a DNS zone file.

    netsec.ethz.ch.         300     IN      A       0.0.0.0
    syssec.ethz.ch.         300     IN      A       0.0.0.0
    _acme-challenge.syssec.ethz.ch. 300     IN      TXT     "8ygi7wK2k8Es-aBK7JuhA091MGnYhrw7cVr8aZ8dm-w"
    _acme-challenge.netsec.ethz.ch. 300     IN      TXT     "MeWcRRcEX0gG5KEvZ24sQZTCYNxl_x4bHJhKMnKKZkI"

    Args:
        domains (list[str]): _description_
        address (str): _description_
        domains_and_rdata (list[tuple[str, str]]): _description_

    Returns:
        str: _description_
    """
    zone: str = ""

    for domain in domains:
        a_record = RR(
            rname=DNSLabel(domain),
            rtype=QTYPE.A,
            ttl=TTL,
            rdata=A(address),
        )
        zone += a_record.toZone() + "\n"

    for domain, data in domains_and_rdata:
        txt_record = RR(
            rname=DNSLabel(VALIDATION_PREFIX + domain),
            rtype=QTYPE.TXT,
            ttl=TTL,
            rdata=TXT(data),
        )
        zone += txt_record.toZone() + "\n"

    return zone


class ACME_DNS_Server:
    """
    A DNS server that responds to all A-record queries with the IPv4 address provided by the ACME server.

    Arguments:
        dns_zone {str} -- The DNS zone to which the DNS server will respond.
        ip_addr {str} -- The IP address to which the DNS server will bind.
        port {int} -- The port to which the DNS server will bind.
    """

    def __init__(
        self,
        dns_zone: str,
        ip_addr: str = IP_ADDRESS,
        port: int = PORT,
    ):
        self.resolver: ZoneResolver = ZoneResolver(zone=textwrap.dedent(dns_zone))
        # self.logger = DNSLogger(prefix=False)
        self.udp_server: DNSServer = DNSServer(
            resolver=self.resolver, port=port, address=ip_addr
        )
        self.is_active: bool = False

    def start(self):
        if not self.is_active:
            print("Starting DNS Server...")
            self.udp_server.start_thread()
            self.is_active = True

    def stop(self):
        if self.is_active:
            print("Stopping DNS Server...")
            # self.udp_server.server.server_close()
            self.udp_server.stop()
            self.is_active = False
