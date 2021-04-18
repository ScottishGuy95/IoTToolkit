#!/usr/bin/env python3
"""
Child class of CredentialsParent - Used to test credentials via TELNET login
"""

__author__ = "ScottishGuy95"
__license__ = "MIT"

import telnetlib
import socket
from CredentialsParent import Credentials as Parent


class CredentialsTELNET(Parent):
    def __init__(self):
        # Pulls all its attributes from the Parent class
        super().__init__()

    def attempt_login(self, password):
        """
        Overrides parent class method - Used to attempt to login to the current host device
        :param password: (str) The password that should be used to brute force a login on the TELNET service
        """
        try:
            # Create the telnet object with the current host device
            tn = telnetlib.Telnet(host=self.current_host, timeout=0.5)
            # Send the username details to the device
            tn.read_until(b'login: ', timeout=0.5)
            tn.write((self.current_user + "\r").encode('utf-8'))
            # If a password is supplied, pass the password to the device
            if password:
                tn.read_until(b"Password: ", timeout=0.5)
                tn.write((password + "\r").encode('utf-8'))
            # Check for a valid connection from the supplied list of responses
            # Logging any successful connections in weak_hosts
            num, match, prev = tn.expect([b'Incorrect', b'Welcome'])
            if num == 1:
                self.weak_hosts[self.current_host] = [220, self.current_user, password]
            tn.close()
            return
        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except EOFError:
            pass
        except ConnectionResetError:
            pass

    def get_weak_hosts(self):
        """
        Creates and returns a list of hosts that were successfully brute-forced
        :return: (lst) A list of hosts with weak TELNET credentials
        """
        weak = []
        try:
            for host in self.get_hosts_only():
                # Checks for the response result against each host in the dictionary
                if self.get_TELNET_result(host) == 220:
                    weak.append(host)
        except TypeError:
            pass
        return weak

    def get_TELNET_result(self, host):
        """
        Checks for the TELNET response result for each host
        :param host: (str) The IP address of a device
        :return: (str) Returns the String that came from the TELNET connection attempt
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
        return len(self.get_weak_hosts())
