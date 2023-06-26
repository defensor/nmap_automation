import os
import sys
from dataclasses import dataclass
import socket
from libnmap import parser


@dataclass
class Service:
    ip: str
    port: int
    proto: str
    service: str
    version: str

    def to_csv(self) -> str:
        return "{ip},{port},{proto},{service},{version}\n".format(
            ip=self.ip,
            port=self.port,
            proto=self.proto,
            service=self.service,
            version=self.version,
        )


def print_ports_to_csv(services: list[Service]) -> None:
    csv_file = open("full_open_ports.csv", "w")
    csv_file.write("IP,Port,Protocol,Service,Version\n")
    for service in services:
        csv_file.write(service.to_csv())

    csv_file.close()


def scan_to_services(filepath: str) -> list[Service]:
    services = []
    nm = parser.NmapParser.parse_fromfile(filepath)

    for host in nm.hosts:
        for port in host.get_open_ports():
            nm_service = host.get_service(port[0], port[1])

            service = Service(
                ip=host.address,
                port=port[0],  # port number
                proto=port[1],  # port proto (udp/tcp)
                service=nm_service.service if nm_service else "",
                version=nm_service.banner if nm_service else "",
            )
            services.append(service)

    return services


def exclude_dublicates(services: list[Service]) -> list[Service]:
    # dict for services tree
    # host :str -> port :int -> proto :str -> Service
    hosts: dict[str, dict[int, dict[str, Service]]] = {}

    for service in services:
        host = service.ip
        port = service.port
        proto = service.proto

        # if this is first appearence of this host
        if hosts.get(host) is None:
            hosts[host] = {}
            hosts[host][port] = {}
            hosts[host][port][proto] = service

        # if this is first appearence of this port
        elif hosts[host].get(port) is None:
            hosts[host][port] = {}
            hosts[host][port][proto] = service

        # if this is first appearence of this port/proto combination
        elif hosts[host][port].get(proto) is None:
            hosts[host][port][proto] = service

        # if this host and port already in the dict, then choose the fullest one
        else:
            if not hosts[host][port][proto].version:
                hosts[host][port][proto] = service

    # convert tree to a list
    uniq_services = []
    for host in hosts:
        for port in hosts[host]:
            for proto in hosts[host][port]:
                uniq_services.append(hosts[host][port][proto])

    return uniq_services


def main(argv):
    # receive only argument - path to the dir with nmap reports in xml format
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <reports_dir_path>")
        exit(1)

    input_dir = sys.argv[1]

    if not os.path.exists(input_dir):
        print("Error! Specified reports dir path not exists!")
        exit(1)

    input_files = [f for f in os.listdir(input_dir) if f.endswith(".xml")]

    services = []
    for filepath in input_files:
        services.extend(scan_to_services(os.path.join(input_dir, filepath)))

    ############################################################
    # exclude dublicates and sort

    services = exclude_dublicates(services)
    services.sort(
        key=lambda item: (socket.inet_aton(item.ip), item.port)
    )  # sort primarily by IP and secondary by port number

    ############################################################

    print_ports_to_csv(services)


if __name__ == "__main__":
    main(sys.argv)
