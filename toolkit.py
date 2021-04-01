#!/usr/bin/env python3
"""
The IoT Toolkit scans your network for open ports, weak credentials and devices not using encryption
Then returns all the data in a simple format with clear mitigation options to rectify the vulnerabilities
"""

__author__ = "ScottishGuy95"
__license__ = "MIT"

import ipaddress
import sys

from Logger import Logger
from PingSweep import PingSweep
from PortScan import PortScan
from CredentialsHTTP import CredentialsHTTP
from CredentialsFTP import CredentialsFTP
from CredentialsTELNET import CredentialsTELNET
from Mitigations import Mitigations

toolkit_title = r"""
  _____     _______   _______             _  _     _  _   
 |_   _|   |__   __| |__   __|           | || |   (_)| |  
   | |   ___  | |       | |  ___    ___  | || | __ _ | |_ 
   | |  / _ \ | |       | | / _ \  / _ \ | || |/ /| || __|
  _| |_| (_) || |       | || (_) || (_) || ||   < | || |_ 
 |_____|\___/ |_|       |_| \___/  \___/ |_||_|\_\|_| \__|                                                                                                
"""
log = Logger()
mitigations = Mitigations()


def isValidNetwork(network_Range):
    """
    Used to test if a given network range & CIDR is valid
    :param network_Range: (str) The network range and CIDR
    :return: (boolean) Boolean depending on if the given string is valid or not
    """
    try:
        # Try and create a network object using the given network range
        # If this fails, raises ValueError and returns False
        network = ipaddress.ip_network(network_Range)
        del network
        return True
    except ValueError:
        return False


def main():
    # Used to determine which security scans returned results to later display certain mitigation methods
    ports_found = False
    credentials_found = False
    encryption_found = False
    durations = []

    print(toolkit_title)
    # Ping Sweep
    print('Preparing the ping sweep scan.')
    auto_network = ''
    while auto_network != "yes" and auto_network != "no" and auto_network != "y" and auto_network != "n":
        auto_network = input(
            'Please only enter the network manually if you understand networking notation\nDo you want to enter the '
            'network address or scan manually (Yes or No): ').lower()
    if auto_network == "yes" or auto_network == "y":
        network_range = ''
        # Checks if there is currently a valid network string given, if not, asks until it gets one
        while isValidNetwork(network_range) is False:
            network_to_scan = input(
                "Please enter the IP Address and CIDR notation in the following format: 192.168.0.0/28\n")
            try:
                # Attempts to create given network into an object, if it fails, it must be an invalid network range
                network = ipaddress.ip_network(network_to_scan)
                print('Starting the ping sweep scan. Please wait...')
                ping = PingSweep(network_to_scan)
                break
            except ValueError:
                print('\tError! Invalid network range given. Please ensure format matches 192.168.0.0/28')
    elif auto_network == "no" or auto_network == "n":
        print('Network will be calculated automatically.')
        print('Starting the ping sweep scan. Please wait...')
        ping = PingSweep()
    print('Ping Sweep results have been logged')

    log.write_to_file("Ping Sweep Results")
    log.write_to_file("Scan started from device: " + ping.host_ip)
    log.write_to_file("Network being scanned: " + ping.range_to_scan + "\n")
    log.write_to_file("Hosts found:")
    # Loop through each of the hosts found, getting and storing more specific details in the log file
    for host in ping.get_all_hosts():
        log.write_to_file("IP: " + host + "\tHostname: " + ping.get_hostname(host) + "\tVendor: " + ping.get_vendor(
            host) + "\tMAC: " + ping.get_mac(host))
    log.write_to_file("Total devices found: " + str(ping.total_hosts))
    durations.append(ping.get_scan_time())  # Adds scan duration to list for overview section
    log.write_to_file("Ping sweep scan time: " + str(ping.get_scan_time()) + "s")

    # Port Scanner
    print('\nStarting a port scan on the ' + str(ping.total_hosts) + ' devices found. Please wait...')
    # Create a port scan object with the ping sweep hosts
    port = PortScan(ping.full_hosts)
    log.write_to_file('\nPort Scan Results')
    # Loop through each IP address, each time, running a port scan on that host
    for host in port.get_hosts():
        port.start_scan(host)
        log.write_to_file(
            "Host: " + host + "\tHostname: " + ping.get_hostname(host) + "\tVendor: " + ping.get_vendor(host))
        # Logs the port details on each host
        for each_port in sorted(port.get_hosts_ports(host)):
            log.write_to_file("Port: " + str(each_port) + "\tService: " + port.get_service(each_port))
        log.write_to_file("Total ports detected: " + str(len(port.get_hosts_ports(host))))
        # Used to check if any ports were found, used later for mitigations
        if len(port.get_hosts_ports(host)) >= 1:
            ports_found = True
    durations.append(port.get_scan_time())  # Adds scan duration to list for overview section
    log.write_to_file("Port scan scan time: " + str(port.get_scan_time()) + "s")
    print('Port scan results have been logged')

    # Credentials Scan
    # HTTP Scan
    print('\nStarting the Credential scans - HTTP Basic Authentication, FTP and TELNET')
    print('NOTE: Running this scan multiple time on the same devices may return different successful usernames '
          'and passwords. This would mean that your device can be logged in either:\nwithout any credentials or with a'
          ' range of weak credentials or with any credentials, all of which means it is insecure. ')
    print('\nStarting a HTTP scan to test for weak credentials on the ' + str(ping.total_hosts) + ' devices found. '
                                                                                                  'Please wait...')
    log.write_to_file('\nCredential Scans')
    log.write_to_file('HTTP Basic Authentication Results')
    credHTTP = CredentialsHTTP()
    # Checks each IP address for a web interface and attempts login
    for host in ping.get_all_hosts():
        credHTTP.check_url_code(host)
    # For each weak host, log the username and password used
    for host in credHTTP.get_weak_hosts():
        username = credHTTP.get_weak_username(host)
        password = credHTTP.get_weak_password(host)
        log.write_to_file(
            "Host: " + host + "\tHostname: " + ping.get_hostname(host) + "\tVendor: " + ping.get_vendor(host))
        log.write_to_file("\tUsername: " + username + "\tPassword: " + password)
    log.write_to_file("Total hosts using weak HTTP credentials: " + str(credHTTP.get_total_weak_hosts()))
    # Checks if any devices had weak credentials, used later for mitigations
    if credHTTP.get_total_weak_hosts() >= 1:
        credentials_found = True
    durations.append(credHTTP.get_scan_time())  # Adds scan duration to list for overview section
    log.write_to_file("HTTP Basic Authentication scan time: " + str(credHTTP.get_scan_time()) + "s")

    # Get a list of hosts that had the FTP port open
    list_FTP_hosts = port.get_hosts_by_port(21)
    print('Starting a FTP scan to test for weak credentials on the %s hosts that had the FTP port (port 21) open. '
          'Please wait...' % str(len(list_FTP_hosts)))
    log.write_to_file('\nFTP Results')
    credFTP = CredentialsFTP()
    # For each host using FTP, pass it a username and attempt login using that username
    for host in list_FTP_hosts:
        for name in credFTP.user_list:
            credFTP.start_scan(host, name)
    # Log the username and password used to login to that device via FTP
    for host in credFTP.get_weak_hosts():
        username = credFTP.get_weak_username(host)
        password = credFTP.get_weak_password(host)
        log.write_to_file(
            "Host: " + host + "\tHostname: " + ping.get_hostname(host) + "\tVendor: " + ping.get_vendor(host))
        log.write_to_file("\tUsername: " + username + "\tPassword: " + password)
    log.write_to_file("Total hosts using weak FTP credentials: " + str(credFTP.get_total_weak_hosts()))
    # Checks if any devices had weak credentials, used later for mitigations
    if credFTP.get_total_weak_hosts() >= 1:
        credentials_found = True
    durations.append(credFTP.get_scan_time())  # Adds scan duration to list for overview section
    log.write_to_file("FTP scan time: " + str(credFTP.get_scan_time()) + "s")

    # Gets a list of hosts that have the TELNET port open
    list_TELNET_hosts = port.get_hosts_by_port(23)
    print('Starting a TELNET scan to test for weak credentials on the %s hosts that had the TELNET port (port 23) '
          'open. Please wait...' % str(len(list_TELNET_hosts)))
    log.write_to_file('\nTELNET Results')
    credTELNET = CredentialsTELNET()
    # For each TELNET enabled host, pass it a username and attempt login over TELNET port
    for host in list_TELNET_hosts:
        for name in credTELNET.user_list:
            credTELNET.start_scan(host, name)
    # Log the username and password pairs used to login to that host via TELNET
    for host in credTELNET.get_weak_hosts():
        username = credTELNET.get_weak_username(host)
        password = credTELNET.get_weak_password(host)
        log.write_to_file(
            "Host: " + host + "\tHostname: " + ping.get_hostname(host) + "\tVendor: " + ping.get_vendor(host))
        log.write_to_file("\tUsername: " + username + "\tPassword: " + password)
    log.write_to_file("Total hosts using weak TELNET credentials: " + str(credTELNET.get_total_weak_hosts()))
    # Checks if any devices made use of weak credentials, used later for mitigations
    if credTELNET.get_total_weak_hosts() >= 1:
        credentials_found = True
    durations.append(credTELNET.get_scan_time())  # Adds scan duration to list for overview section
    log.write_to_file("TELNET scan time: " + str(credTELNET.get_scan_time()) + "s\n")
    print('Credential scan results have been logged')

    # Mitigations
    print('\n[!] During the scan, some security risks may have been found. Below are some tips on how to increase the '
          'security of your IoT devices')
    # Depending on the security issue detected, it will print mitigation methods relating to that area
    # It will select 2 random messages from that area, then display 2 random messages about general cyber sec
    if ports_found:
        print('\n' + mitigations.get_port_desc())
        for msg in mitigations.get_random_messages('port'):
            print('* ' + msg)
    if credentials_found:
        print('\n' + mitigations.get_credentials_desc())
        for msg in mitigations.get_random_messages('credentials'):
            print('* ' + msg)
    if encryption_found:
        print('\n' + mitigations.get_encryption_desc())
        for msg in mitigations.get_random_messages('encryption'):
            print('* ' + msg)
    print('\nGeneral Cyber Security Tips')
    for msg in mitigations.get_random_messages('general'):
        print('* ' + msg)

    # Overview section
    # Used to give the user a quick overview of the scan results
    log.write_to_file("Overview Section")
    log.write_to_file("Ping Sweep results: " + str(ping.total_hosts) + "\tDuration: " + str(durations[0]))
    log.write_to_file("Number of devices checked for open ports: " + str(len(port.get_hosts())) + "\tDuration: " +
                      str(durations[1]))
    log.write_to_file("Number of devices checked for HTTP login: " + str(len(credHTTP.get_hosts_only())) + "\tFound: " +
                      str(credHTTP.get_total_weak_hosts()) + "\tDuration: " + str(durations[2]))
    log.write_to_file("Number of devices checked for FTP login: " + str(len(list_FTP_hosts)) + "\tFound: " +
                      str(credFTP.get_total_weak_hosts()) + "\tDuration: " + str(durations[3]))
    log.write_to_file("Number of devices checked for TELNET login: " + str(len(list_TELNET_hosts)) +
                      "\tFound: " + str(credTELNET.get_total_weak_hosts()) + "\tDuration: " +
                      str(durations[4]) + "\n")


if __name__ == "__main__":
    try:
        main()
        print("\nScan results saved to file: " + log.get_filename())
        log.end()
    except KeyboardInterrupt:
        log.write_to_file("Scan was canceled by the user.\n")
        log.end()
        print('\n\nUser has cancelled the program - Ending scan\nThank you for using the IoT Toolkit!')
        sys.exit()
