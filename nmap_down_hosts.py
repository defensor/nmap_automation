import getopt
import os
import sys

from libnmap import parser

NMAP_TEMPLATE: str = (
    "sudo nmap {keys} {ip} -oN {report_filename}.txt -oX {report_filename}.xml"
)
REPORT_NAME_TEMPLATE: str = "nmap_{keys}_{ip}"
KEYS: str = "-sS -Pn -p-"


def scan_without_ping(address):
    report_filename = REPORT_NAME_TEMPLATE.format(
        keys=KEYS.replace(" ", "_"), ip=address
    )

    nmap_command = NMAP_TEMPLATE.format(
        keys=KEYS, ip=address, report_filename=report_filename
    )

    os.system(nmap_command)


def main(argv):
    input_dir: str = ""

    ##################################################################################
    # parse arguments

    try:
        opts, args = getopt.getopt(argv, "hi:t:")
    except getopt.GetoptError:
        print("python nmap_down_hosts.py -i <reportsdir> -t <targetsfile>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print("python nmap_down_hosts.py -i <reportsdir> -t <targetsfile>")
            sys.exit()
        elif opt == "-i":
            input_dir = arg
        elif opt == "-t":
            all_targets_file = arg

    ##################################################################################
    # parse previous network scan results

    input_files = [
        f
        for f in os.listdir(input_dir)
        if f.startswith("nmap_-sS_-p-") and f.endswith(".xml")
    ]

    filepath: str
    up_hosts: list[str] = []
    for filepath in input_files:
        nm = parser.NmapParser.parse_fromfile(filepath)
        for host in nm.hosts:
            if host.is_up():
                up_hosts.append(host.address)

    with open(all_targets_file, "r") as all_targets:
        for address in all_targets.readlines():
            if address.strip() not in up_hosts:
                scan_without_ping(address.strip())


if __name__ == "__main__":
    main(sys.argv[1:])


#######################################################################
# recieves dir with report and file with IP addresses
# enumerates all IP addresses and check which one already has reports
# and perform no-ping scan for the rest
#######################################################################
