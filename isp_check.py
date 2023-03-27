import os
import sys
from ipwhois import IPWhois
from collections import defaultdict


def get_isp(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        return results.get("asn_description", "Unknown")
    except:
        return "Unknown"


def read_ips_from_file(file_path):
    with open(file_path, "r") as file:
        return [line.strip() for line in file.readlines()]


def remove_selected_isps_ips(file_path, selected_isps):
    ips = read_ips_from_file(file_path)
    new_ips = []

    for ip in ips:
        isp = get_isp(ip)
        if isp not in selected_isps:
            new_ips.append(ip)

    with open(file_path, "w") as file:
        for ip in new_ips:
            file.write(ip + "\n")


def main():
    if len(sys.argv) != 2:
        print("Usage: python isp_check.py <file_path>")
        exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print("The specified file does not exist.")
        exit(1)

    ips = read_ips_from_file(file_path)
    isp_counts = defaultdict(int)

    for ip in ips:
        isp = get_isp(ip)
        isp_counts[isp] += 1

    print("ISP list:")
    for isp, count in isp_counts.items():
        print(f"{isp}: {count} IPs")

    selected_isps = input("\nEnter the ISPs you want to remove (. separated): ").split(".")

    remove_selected_isps_ips(file_path, [isp.strip() for isp in selected_isps])

    print("Selected ISP IPs have been removed from the file.")


if __name__ == "__main__":
    main()
