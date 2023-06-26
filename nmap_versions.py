import getopt
import os
import sys

from libnmap import parser

nmap_command_template: str = (
    "sudo nmap {keys} {ip} -oN {report_filename}.txt -oX {report_filename}.xml"
)
report_filename_template: str = "nmap_{keys}_{ip}_X"
keys_template: str = "-sS -Pn -sV -p{ports}"


def scan_services(host, report_dir):
    keys = keys_template.format(
        ports=",".join([str(port[0]) for port in host.get_open_ports()])
    )

    report_filename = report_filename_template.format(
        keys=keys.replace(" ", "_"), ip=host.address
    )

    nmap_command = nmap_command_template.format(
        keys=keys,
        ip=host.address,
        report_filename=os.path.join(report_dir, report_filename),
    )

    os.system(nmap_command)


def main(argv):
    input_dir: str = ""
    report_dir: str = "."

    try:
        opts, args = getopt.getopt(argv, "hio:")
    except getopt.GetoptError:
        print(
            "python nmap_scan_version.py -i <in_reports_directory> -o <out_reports_directory>"
        )
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print(
                "python nmap_scan_version.py -i <in_reports_directory> -o <out_reports_directory>"
            )
            sys.exit()
        elif opt == "-i":
            input_dir = arg
        elif opt == "-o":
            report_dir = arg

    input_files = [
        f for f in os.listdir(input_dir) if f.startswith("nmap_") and f.endswith(".xml")
    ]

    filepath: str
    for filepath in input_files:
        nm = parser.NmapParser.parse_fromfile(os.path.join(input_dir, filepath))
        for host in nm.hosts:
            if host.get_open_ports():
                scan_services(host, report_dir)


if __name__ == "__main__":
    main(sys.argv[1:])
