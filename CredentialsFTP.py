#!/usr/bin/env python3
"""
Child class of CredentialsParent - Used to test credentials via FTP login
"""

__author__ = "ScottishGuy95"
__license__ = "MIT"

import ftplib
import socket
from CredentialsParent import Credentials as Parent


class CredentialsFTP(Parent):
    def __init__(self):
        # Pulls all its attributes from the Parent class
        super().__init__()

    def attempt_login(self, password):
        """
        Overrides parent class method - Used to attempt to login to the current host device
        :param password: (str) The password that should be used to brute force a login on the FPT service
        """
        try:
            # Creates a FTP object and attempts to connect to the given host with credentials
            ftp = ftplib.FTP(host=self.current_host, user=self.current_user, passwd=password, timeout=0.5)
            # Checks if the device returned a message
            if "successful" in str(ftp.getwelcome()):
                self.weak_hosts[self.current_host] = [220, self.current_user, password]
            ftp.close()
            pass
        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except EOFError:
            pass

    def get_weak_hosts(self):
        """
        Creates and returns a list of hosts that were successfully brute-forced
        :return: (lst) A list of hosts with weak FTP credentials
        """
        weak = []
        try:
            for host in self.get_hosts_only():
                # Checks for the success code against each host in the dictionary
                if self.get_ftp_code(host) == 220:
                    weak.append(host)
        except TypeError:
            pass
        return weak

    def get_ftp_code(self, host):
        """
        Checks for the FTP response code for each host
        :param host: (str) The IP address of a device
        :return: (str) Returns an the status code value from the FTP login
        """
        return self.weak_hosts.get(host)[0]

    def get_weak_username(self, host):
        """
        Gets the username that was used to login
        :param host: (str) The IP address of a device
        :return: (str) The username used to login or a space for no username needed
        """
        try:
            return self.weak_hosts.get(host)[1]
        except IndexError:
            return " "

    def get_weak_password(self, host):
        """
        Gets the password that was used to login
        :param host: (str) The IP address of a device
        :return: (str) The password used to login or a space for no password needed
        """
        try:
            return self.weak_hosts.get(host)[2]
        except IndexError:
            return " "

    def get_total_weak_hosts(self):
        """
        Gets the total amount of weak hosts
        :return: (int) The amount of hosts with weak credentials
        """
        return len(self.weak_hosts)
