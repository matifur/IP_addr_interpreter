# IP_addr_interpreter

This project is a command-line networking tool that provides detailed information about IP addresses, subnet masks, and network properties. It supports both IPv4 and IPv6 and can process IP addresses in CIDR notation or with decimal subnet masks.
Features

✅ Validates and parses IP addresses and subnet masks
✅ Determines the network address, broadcast address, and number of hosts
✅ Identifies special IP address categories (e.g., Private, Loopback, Multicast)
✅ Converts IP addresses to binary and hexadecimal formats
✅ Checks if an IP address belongs to a specific subnet
Usage

Run the script with an IP address in CIDR notation or with a subnet mask:
python ip_tool.py 192.168.1.1/24
python ip_tool.py 192.168.1.1 255.255.255.0

Check if an IP belongs to a subnet:
python ip_tool.py 192.168.1.100 -n 192.168.1.0/24

Show binary or hexadecimal representation:
python ip_tool.py 192.168.1.1/24 -b -x
Requirements

    Python 3.x

    ipaddress module (built-in with Python 3)

