import getopt
import os
import sys

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

    try:
        opts, args = getopt.getopt(argv, "hto:")
    except getopt.GetoptError:
        print("python multiple_nmap.py -t <targetsfile> -o <outputdir> [nmap keys]")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print("python multiple_nmap.py -t <targetsfile> -o <outputdir> [nmap keys]")
            print("default keys: -sS -p-")
            sys.exit()
        elif opt == "-t":
            inputfile = arg
        elif opt == "-o":
            outputdir = arg
        else:
            nmap_args.append(arg)

    if nmap_args:
        nmap_args = " ".join(args)
    else:
        nmap_args = stealth_scan_all_ports_args

    print("input file: " + inputfile)
    print("output dir: " + outputdir)
    with open(inputfile, "r") as ips_file:
        ips = ips_file.readlines()
        for ip in ips:
            print(f"Scan ip address/addresses {ip.strip()}...\t")
            scan(ip.strip(), outputdir, nmap_args)
            print("Done!\n")


if __name__ == "__main__":
    main(sys.argv[1:])
