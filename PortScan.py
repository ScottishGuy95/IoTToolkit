#!/usr/bin/env python3
"""
Runs a port scan on each host in the network
"""

__author__ = "ScottishGuy95"
__license__ = "MIT"

import socket
import threading
from queue import Queue
import time


class PortScan:
    def __init__(self, ping_sweep_results):
        self.start_time = time.time()
        self.scans = Queue()  # Used to store each thread
        # The below variable will later come from PingSweep.py in the following format
        #   Dictionary - Keys are IP addresses, value per key is a list, with MAC/Vendor
        self.hosts = ping_sweep_results
        self.current_host = ''
        self.open_ports = {i: [] for i in self.hosts.keys()}  # Each host IP is a key, list of values for ports

    def port_scan(self, port):
        """
        Checks the state of a given port
        :param port: (int) The port of a given device to test if it is UP or not
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Give up after 3 seconds, should have a response by then
        try:
            # Try and connect, any failures mean the port is not up
            sock.connect((self.current_host, port))
            # Add the port to the given hosts list of port numbers
            self.open_ports.setdefault(self.current_host, []).append(port)
        except socket.error:
            pass  # Pass on any errors, so the scan continue
        sock.close()

    def threader(self):
        """
        For each port scan request and for each thread created, will run until all threads are complete
        """
        while True:
            worker = self.scans.get()
            self.port_scan(worker)
            self.scans.task_done()

    def start_threads(self):
        """
        Creates and manages the threads that help improve the port scan speed
        """
        # Start 100 threads that will run the port scans
        try:
            for x in range(100):
                # Call the threader, then class them as daemon
                # to ensure program does not end until threads are done
                t = threading.Thread(target=self.threader)
                t.daemon = True
                t.start()
        except RuntimeError:
            pass

        # Add the ports to our Queue
        for worker in range(1, 1000):
            self.scans.put(worker)

        # Wait until all the workers are done
        self.scans.join()

    def start_scan(self, host_to_scan):
        """
        Runs a port scan on the given host
        :param host_to_scan: (srt) The IP address of a device to scan its ports
        """
        # Sets the IP address of the device to scan and starts the threads and port scan
        self.current_host = host_to_scan
        self.start_threads()

    def get_hosts_ports(self, host):
        """
        Retrieves a list of ports that were open on a given host
        :param host: (str) The IP address of a device
        :return: (lst) A list of open ports
        """
        ports = self.open_ports.get(host)
        return ports

    def get_hosts(self):
        """
        Pulls the list of IP addresses from the hosts dictionary
        :return: (lst) A list of IP addresses
        """
        return self.hosts.keys()

    def get_service(self, port):
        """
        Returns the service name of a given port
        :param port: (int) The port to check
        :return: (str): Returns the port service name or 'Unknown' if there is an issue
        """
        try:
            service = socket.getservbyport(port)
            return service
        except OSError:
            return 'Unknown'

    def get_hosts_by_port(self, port):
        """
        Checks which hosts had the given port open
        :param port: (int) The port number to check
        :return: (lst) A list of host IP addresses
        """
        contains_port = []
        for host in self.open_ports.keys():
            if port in self.open_ports.get(host):
                contains_port.append(host)
        return contains_port

    def get_scan_time(self):
        """
        Gets the duration from now since the object was created
        Used to get the total duration of the Port Scan in seconds
        :return: (str) The duration in seconds
        """
        return str(round(time.time() - self.start_time))

    def get_total_ports(self):
        """
        Gets the total ports detected from all hosts
        :return: (int) The number of ports detected from the entire port scan
        """
        total = 0
        for x in self.open_ports.values():
            total += len(x)
        return total
