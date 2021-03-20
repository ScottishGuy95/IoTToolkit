#!/usr/bin/env python3
"""
Pings each possible IP address in a network to see what hosts are UP
"""

__author__ = "ScottishGuy95"
__license__ = "MIT"

import re
import subprocess
import platform
import ipaddress
import threading
from queue import Queue
import socket
import requests
import time


def get_host_ip():
    """
    Gets the computers IP address
    :return: (str) IP address of the computer
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))  # Runs a basic connection to external address
    # Takes the IP from the list
    ip = sock.getsockname()[0]
    sock.close()
    return ip


def get_netmask(ip):
    """
    Takes an IP address and returns the subnet mask for that IP
    :param ip:(str) The IP address of a host device
    :return mask: (str) The subnet mask of the given IP
    """
    mask = ''
    # Check what OS is running, as the netmask is retrieved differently depending on OS
    if platform.system() == "Windows":
        # Run the windows command ipconfig and store results
        proc = subprocess.Popen('ipconfig', stdout=subprocess.PIPE)
        # Find the IP address from the data
        while True:
            line = proc.stdout.readline()
            if ip.encode() in line:
                break
        # Take the IP string, removing the irrelevant data
        mask = proc.stdout.readline().rstrip().split(b':')[-1].replace(b' ', b'').decode()
    else:
        # Run the linux command ifconfig and store resulting data
        proc = subprocess.Popen('ifconfig', stdout=subprocess.PIPE)
        # Find the IP address
        while True:
            line = proc.stdout.readline()
            if ip.encode() in line:
                break
        # Remove the spacing and escape characters
        theMask = line.rstrip().split(b':')[-1].replace(b' ', b'').decode().split('broadcast')[0]
        # Loop through the string from the end to start, pulling out each number and dot
        # Until it reaches the first character, leaving only the netmask value
        for x in theMask[::-1]:
            if x.isdigit() or x == '.':
                mask += x
                continue
            else:
                break
        # Reverse the netmask so its in the correct direction
        mask = mask[::-1]
    if len(mask) > 1:
        return mask
    else:
        print('Error! Given details are invalid and the mask was not able to be defined.\nPlease ensure a valid IP is '
              'given.')


def get_cidr(mask):
    """
    Takes a given subnet mask and converts it to CIDR notation
    :param mask: (str) The subnet mask to convert
    :return: (int): The CIDR value
    """
    # Converts each block of the given mask into its binary version, and counts the 1s
    return sum(bin(int(x)).count('1') for x in mask.split('.'))


def get_network_range(ip, cidr):
    """
    Creates the local network IP range and the CIDR into a single String and returns it
    :param: ip: (str) The IP address of the host device
    :param: cidr: (str) The CIDR notation to add to the final string
    :return: (str) The local network range in IP/CIDR format
    """
    host_ip = ip.split('.')  # Split the IP into each part
    # Check the CIDR value and replace each block with 0s as required to match the mask
    if 24 <= cidr <= 32:
        host_ip[-1] = 0
    elif 16 <= cidr <= 24:
        host_ip[-1] = 0
        host_ip[-2] = 0
    elif 8 <= cidr <= 16:
        host_ip[-1] = 0
        host_ip[-2] = 0
        host_ip[-3] = 0
    # Combine the values into a final IP/CIDR string
    return '.'.join(str(x) for x in host_ip) + '/' + str(cidr)


def check_mac(host):
    """
    Attempts to retrieve the MAC address of a given device using OS commands
    :param host: (str) The IP address of a given device on the network
    :return: (str) The name of a device or Unknown in case of any errors
    """
    arp = subprocess.Popen(['arp', '-a', host], stdout=subprocess.PIPE).communicate()[0].decode('utf-8')
    # Linux separates MACs using ':'. Windows separates MACs using '-'
    rule = re.compile(r'([0-9a-zA-Z](\:|-?)){12}')
    result = re.search(rule, arp)
    # Returns None if no match was found during the regex search
    if result is not None:
        return result.group()
    else:
        return 'Unknown'


def check_vendor(mac, connection):
    """
    Makes use of a free API to check a MAC addresses vendor
    Requires self.internet_con to be True
    :param connection: (Boolean) True if the device has an internet connection
    :param mac: (str) A MAC address of a given device
    :return: (str) The vendor of a given host devices network card
    """
    if connection:
        try:
            time.sleep(1)  # Free API requires a delay to avoid overloading the service
            vendor_req = requests.get('https://api.macvendors.com/' + mac)
            vendor = vendor_req.content.decode()  # Decode into a readable format
            if 'Not Found' in vendor:
                return 'Unknown'
            return vendor
        except requests.exceptions.ConnectionError:
            return 'Unknown'
        except:
            return 'Unknown'
    else:
        return 'Unknown'


def check_hostname(ip):
    """
    Attempts to get a valid hostname to represent a given IP address
    :param ip: (str) The IP address of a given device on a network
    :return: (str) The name of a given device, or Unknown for any other situations
    """
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except socket.herror:
        return 'Unknown'


def check_internet_connection():
    """
    Attempts to connect to online services most likely to be available and returns boolean if it connects
    Used as a way of detecting if the host device has an internet connection or not
    :return:(boolean) True or False depending on if theres a internet connection
    """
    test_urls = ['https://1.1.1.1/', 'https://www.google.com']
    for url in test_urls:
        try:
            requests.get(url)
            return True
        except:
            continue
    return False


class PingSweep:
    thread_lock = threading.Lock()

    def __init__(self, manual=False):
        self.start_time = time.time()
        self.pings = Queue()
        self.host_ip = get_host_ip()  # The IP of the host running the scan
        self.subnet_mask = get_netmask(self.host_ip)
        self.cidr = get_cidr(self.subnet_mask)
        if manual is False:
            self.range_to_scan = get_network_range(self.host_ip, self.cidr)
            print('Detected network: ' + str(self.range_to_scan))
        else:
            self.range_to_scan = manual
        # A list of all possible IP addresses to ping on the network
        self.network = list(ipaddress.ip_network(self.range_to_scan).hosts())
        self.hosts_list = []
        self.internet_con = check_internet_connection()
        if not self.internet_con:
            print('[!] No internet connection detected. Vendor information will be unavailable')
        self.start_threads()
        self.full_hosts = {i: [] for i in self.hosts_list}  # Each host IP is a key, list of values for MAC/Vendor
        # Used to add the MAC/Vendors/Hostnames before the data can be accessed
        self.add_host_details()
        self.total_hosts = len(self.get_all_hosts())

    def threader(self):
        """
            Used for each ping, for each thread created, running until all threads are complete
            """
        while True:
            worker = self.pings.get()
            self.ping_sweep(worker)
            self.pings.task_done()

    def start_threads(self):
        """
        Creates and manages the threads that help improve the ping speed
        """
        # Start 100 threads that will run each ping
        for x in range(100):
            # Call the threader, then class them as daemon
            # to ensure program does not end until threads are done
            t = threading.Thread(target=self.threader)
            t.daemon = True
            t.start()
        # Add each host ot our Queue
        for host in range(len(self.network)):
            self.pings.put(host)
        # Wait until all the workers are done
        self.pings.join()

    def ping_sweep(self, host):
        """
        Pings the given IP address and stores any hosts that are up
        :param host: (str) The IP address to ping
        """
        # Check what OS is running to run a different ping command
        if platform.system().lower() == "windows":
            # Windows: -n sets how many requests to send, -w handles timeout length in seconds
            # Linux: -c sets how many requests to send, -w handles timeout length in seconds
            cmd = ["ping", "-n", "2", "-w", "2", str(self.network[host])]
        else:
            cmd = ["ping", "-c", "2", "-w", "2", str(self.network[host])]
        # Runs the ping command and outputs the data into a readable string
        ping = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0].decode('utf-8')
        # Locks this step until the entire ping sweep is complete
        with self.thread_lock:
            # Checks for strings that are present in successful ping scans only
            # Linux: 64 bytes, Windows: bytes=32
            if "bytes=32" in ping or "64 bytes" in ping:
                self.hosts_list.append(str(self.network[host]))  # Adds the valid IP address to the list

    def get_all_hosts(self):
        """
        Returns the list of IP addresses
        :return: (lst) The results of the ping sweep scan in a list
        """
        self.hosts_list = sorted(self.hosts_list, key=lambda ip: int(ip.split('.')[-1]))
        return self.hosts_list

    def add_host_details(self):
        """
        Updates the host dictionary with the MAC addresses, hostnames and Vendors where possible
        Doing this now means all the data is accessible for the other aspects of the program
        """
        for host in self.full_hosts.keys():
            self.full_hosts.setdefault(host, []).append(check_mac(host))
            self.full_hosts.setdefault(host, []).append(check_vendor(self.full_hosts.get(host)[0], self.internet_con))
            self.full_hosts.setdefault(host, []).append(check_hostname(host))

    def get_mac(self, host):
        """
        Gets the MAC address for the given host
        :param host: (str) The IP address of a device on the network
        :return: (str) The MAC address of a device or 'Unknown'
        """
        return self.full_hosts.get(host)[0]

    def get_vendor(self, host):
        """
        Gets the Vendor for the given host, always returns 'Unknown' if there is no internet connection
        :param host: (str) The IP address of a device on the network
        :return: (str) The vendor name of the device
        """
        return self.full_hosts.get(host)[1]

    def get_hostname(self, host):
        """
        Gets the hostname for the given host
        :param host: (str) The IP address of a device on the network
        :return: (str) The hostname of a device
        """
        return self.full_hosts.get(host)[2]

    def get_scan_time(self):
        """
        Gets the duration from now since the object was created
        Used to get the total duration of the PingSweep in seconds
        :return: (str) The duration of the PingSweep objects operations in seconds
        """
        return str(round(time.time() - self.start_time))
