import re
import os
from dataclasses import dataclass
import socket
import sys

# nmapt txt format example
##############################################################
# Nmap scan report for host-some.domain.net (111.1.111.1)    #
# Host is up (0.0011s latency).                              #
# Not shown: 65534 filtered tcp ports (no-response)          #
# PORT    STATE SERVICE  VERSION                             #
# 443/tcp open  https    Nginx                               #
##############################################################

HOST_START_LINE = "Nmap scan report for "
PORT_START_LINE = "PORT "
PORT_REGEX_PATTERN = r"^\d+/(tcp|udp).*"  # 443/tcp
IP_REGEX_PATTERN = r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}"
PORT_PARSING_PATTERN = r"(\d+)/(tcp|udp)\s+([\w|]+)\s+(\S+)\s*(.*)?$"


@dataclass
class Service:
    ip: str
    port: int
    proto: str
    service: str
    version: str


def nmap_txt_parse(filepath: str) -> list[Service]:
    # returns a list
    services = []

    with open(filepath, "r") as nmap_report:
        host_ip = ""
        looking_for_ports = False

        for raw_line in nmap_report:
            line = raw_line.strip()

            # get host ip address from the first host report line
            if line.startswith(HOST_START_LINE):
                match = re.search(IP_REGEX_PATTERN, line)
                if not match:
                    print(
                        f"Error! Report {filepath} is invalid. Host line '{line}' doesn't contain valid IP address!"
                    )
                    exit()

                host_ip = match[0]

            # if services table's header found, then following strings will be services descriptions
            elif line.startswith(PORT_START_LINE):
                looking_for_ports = True

            # if found an empty line in services table then it is the end of the table
            elif looking_for_ports and line == "":
                looking_for_ports = False

            # if there is a line in services table and it starts with <port_num>/<proto> then it is service description
            elif looking_for_ports and re.match(PORT_REGEX_PATTERN, line):
                results = re.search(PORT_PARSING_PATTERN, line)
                if not results:
                    print(
                        f"Error! Report {filepath} is invalid. Service line '{line}' has invalide structure!"
                    )
                    exit()

                port, proto, status, service, version = results.groups()

                # filter only open services
                if status != "open":
                    continue

                service = Service(
                    ip=host_ip,
                    port=int(port),
                    proto=proto,
                    service=service,
                    version=version,
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


if __name__ == "__main__":
    # receive only argument - path to the dir with nmap reports in txt format
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <reports_dir_path>")
        exit()

    input_dir = sys.argv[1]

    if not os.path.exists(input_dir):
        print("Error! Specified reports dir path not exists!")
        exit()

    ############################################################
    # import nmap results from txt reports

    services = []

    for filename in os.listdir(input_dir):
        if not filename.endswith(".txt"):
            continue

        filepath = os.path.join(input_dir, filename)
        services.extend(nmap_txt_parse(filepath))

    ############################################################
    # exclude dublicates and sort

    services = exclude_dublicates(services)
    services.sort(
        key=lambda item: (socket.inet_aton(item.ip), item.port)
    )  # sort primarily by IP and secondary by port number

    ############################################################
    # export to csv

    with open("nmap_results.csv", "w") as out_csv:
        out_csv.write("IP,Port,Protocol,Service,Version\n")

        for service in services:
            service_string = "{ip},{port},{proto},{service},{version}".format(
                ip=service.ip,
                port=service.port,
                proto=service.proto,
                service=service.service[:-1]
                if service.service.endswith("?")
                else service.service,
                version=service.version,
            )

            out_csv.write(service_string + "\n")


#####################################################
# parses nmap txt reports
# produces csv file in format:
# ip, port, proto, service, version
#####################################################
