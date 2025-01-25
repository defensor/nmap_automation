import os
import sys
import argparse
import ipaddress

nmap_command_template: str = (
    "sudo nmap {keys} {ip} -oN {report_filename}.txt -oX {report_filename}.xml"
)
report_filename_template: str = "nmap_{keys}_{ip}_X"

stealth_scan_all_ports_args: str = "-sS -p-"


def scan(ip: str, outputdir: str, nmap_args: str):
    report_filename = report_filename_template.format(
        keys=nmap_args.replace(" ", "_"), ip=ip.replace("/", "_")
    )
    nmap_command = nmap_command_template.format(
        keys=nmap_args,
        ip=ip,
        report_filename=os.path.join(outputdir, report_filename),
    )

    os.system(nmap_command)


def main(argv):
    inputfile = ""
    outputdir = "."
    nmap_args = []


    parser = argparse.ArgumentParser(description="Nmap script")
    parser.add_argument("-i", "--input", help="Path to targets file", required=False)
    parser.add_argument("-t", "--target", help="Targets", required=False)
    parser.add_argument("-o", "--output", help="Path to output directory")
    parser.add_argument("nmap_args", nargs=argparse.REMAINDER, help="Additional Nmap arguments")

    args = parser.parse_args()

    target_ips = []

    if args.input is not None: # targets - file with IPs list
        inputfile = args.input
        print("input file: " + inputfile)
        with open(inputfile, "r") as ips_file:
            target_ips = ips_file.readlines()
    elif args.target is not None: # targets specified in arg
        target_items = args.targets.split(',')
        for item in target_items:
            if "/" in item: # network
                try:
                    network = ipaddress.ip_network(item, strict=False)
                    target_ips.extend(str(ip) for ip in network)
                except ValueError as e:
                    print(f"Invalid network: {item} ({e})")
            elif "-" in item: # range
                try:
                    base, end_range = item.rsplit('.', 1)
                    start, end = map(int, end_range.split('-'))
                    target_ips.extend(f"{base}.{i}" for i in range(start, end + 1))
                except ValueError as e:
                    print(f"Invalid range: {item} ({e})")
            else: # IP-address
                try:
                    ip = ipaddress.ip_address(item)
                    target_ips.append(str(ip))
                except ValueError as e:
                    print(f"Invalid IP: {item} ({e})")
    else:
        print("Error: either -t or -i flag should be specified")
        exit(-1)

    if args.output:
        outputdir = args.output

    if args.nmap_args:
        nmap_args = list(args.nmap_args[0].split(" "))
    
    if nmap_args:
        nmap_args = " ".join(nmap_args)
    else:
        nmap_args = stealth_scan_all_ports_args

    print("output dir: " + outputdir)

    for ip in target_ips:
        print(f"Scan ip address/addresses {ip.strip()}...\t")
        scan(ip.strip(), outputdir, nmap_args)
        print("Done!\n")


if __name__ == "__main__":
    main(sys.argv[1:])
