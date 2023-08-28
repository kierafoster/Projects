import telnetlib
import csv
import requests
import nmap
import pynetbox

def telnet_into_ont(site, ip_address, username, password):
    # Establish a telnet connection to the ONT
    tn = telnetlib.Telnet(ip_address)

    # Login
    tn.read_until(b"Username:")
    tn.write(username.encode('ascii') + b"\n")
    tn.read_until(b"Password:")
    tn.write(password.encode('ascii') + b"\n")

    # Retrieve port map data
    tn.write(b"show portmap\n")
    portmap_data = tn.read_all().decode('ascii')

    # Close connection
    tn.close()

    return portmap_data

def parse_portmap_data(portmap_data):
    # Parse the data
    parsed_data = []
    lines = portmap_data.split('\n')
    for line in lines:
        if line:
            port, mac_address = line.split(',')
            parsed_data.append([port, mac_address])
    return parsed_data

def get_ip_address(mac_adress):
    nm = nmap.PortScanner()

    # Determine the IP range
    # Store in the results variable
    ip_range = f"10.249.{str(site)}.2-253"
    results = nm.scan(ip_range, ports="23", arguments="-sS")

    # Use mac address as an identifier/filter to select the correct devices
    identifier = "00:01:47"

    ip_addresses = []


    for key in results["scan"]:
        try:
            mac_addresses = results["scan"][key]["addresses"]["mac"]
            # Filter and store IP addresses based on identifier 
            if identifier in mac_addresses:
                ip_addresses.append(key)
        except KeyError:
            pass

    return ip_addresses

def associate_mac_with_ip(parsed_data):
    # Create a list with the updated data 
    updated_data = []
    for entry in parsed_data:
        port, mac_address = entry
        ip_address = get_ip_address(mac_address)
        updated_data.append([port, mac_address, ip_address])
    return updated_data

def populate_netbox(netbox_url, token, site_name, ont_data):
    # Connect to NetBox API
    nb = pynetbox.api(url=netbox_url, token=token)

    site = nb.dcim.sites.get(name=site_name)

    # Iterate over ONT data
    for ont_entry in ont_data:
        port, mac_address = ont_entry
        
        # Retrieve IP address for the MAC address 
        ip_address = get_ip_address(mac_address)

        # Create/update the device in NetBox
        device = nb.dcim.devices.get(name=f'ONT-{port}', site_id=site.id)
        if not device:
            device = nb.dcim.devices.create(
                name=f'ONT-{port}',
                device_type=1,  # replace with actual type ID from NetBox
                site=site.id
            )

        # Create/update the interface in NetBox
        interface = nb.dcim.interfaces.get(device_id=device.id, name=port)
        if not connected_device:
            connected_device = nb.dcim.devices.create(
                name=f'Deivce-{mac_address}',
                device_type=2 # replace with type from NetBox
                site=site.id,
                mac_address=mac_address
            )

        # Create/update IP address for the connected device 
        ip_interface = nb.ipam.ip_addresses.get(device_id=connected_device.id, address=ip_address)
        if not ip_interface:
            ip_interface = nb.ipam.ip_addresses.create(
                device=connected_device.id,
                address=ip_address
            )

        # Connect the interface to the connected device
        interface.update(cabled.device=connected_device.id)

    
import utils
import getONT

def associate_mac_ip():
    for ont in port_map_data:
        ont_name = ont['ONT Name']
        mac_address = ont['MAC Address']
        site = ont['Site']

        # Retrieve the IP addresses for the ONT
        ip_addresses = scanONT(site)

        # Associate MAC addresses with IP addresses in NetBox
        for port in ont['Ports']:
            port_name = port['Port Name']
            mac = port['MAC Address']

            # Find corresponding IP address for the MAC address
            ip_address = None
            for ip in ip_addresses:
                if ip['MAC Address'] == mac:
                    ip_address = ip['IP Address']
                    break

            # Update NetBox with MAC and IP address info
            if ip_address:
                netbox_api.update_ont_port(ont_name, port_name, mac, ip_address)

