## Nmap automation scripts

### Multiple nmap

```
multiple_nmap.py -i <targetsfile> -o <outputdir> [nmap args]
```

Scan multiple network targets from `<targetsfile>` file with targets in separate Nmap scans, generates reports into `<outputdir>` directory in XML and TXT formats.
Nmap args can be passed after all other args, by default nmap runs with `-sS -p-` keys.

### Down hosts

```
nmap_down_hosts.py -i <reportsdir> -t <targetsfile>
```

Check which targets from `<targetsfile>` already has scan results in `<reportsdir>` and scan the rest with no-ping scan.

### Versions

```
nmap_scan_version.py -i <in_reports_directory> -o <out_reports_directory>
```

Collect open ports list from nmap reports in xml format from `<in_reports_directory>` directory and runs nmap version scans for this ports.
Version scan reports are saved in XML and TXT format in `<out_reports_directory>` directory.

### XML to CSV

```
nmap_xml_to_csv.py <reportsdir>
```

Converts nmap XML reports from `<reportsdir>` into one csv file in the following format:

```
IP, Port, Proto, Service, Version
```

### TXT to CSV

```
nmap_txt_to_csv.py <reportsdir>
```

Converts nmap TXT reports from `<reportsdir>` into one csv file in the following format:

```
IP, Port, Proto, Service, Version
```
