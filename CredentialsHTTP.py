#!/usr/bin/env python3
"""
Child class of CredentialsParent - Used to test credentials using HTTP Basic Authentication
"""

__author__ = "ScottishGuy95"
__license__ = "MIT"

import requests
from CredentialsParent import Credentials as Parent


class CredentialsHTTP(Parent):
    def __init__(self):
        super().__init__()

    def check_url_code(self, host):
        """
        Connects to a given host and stores the status code
        Attempting logons depending on the status code returned
        :param host: (str) The IP address of a given device
        """
        try:
            req = requests.get("http://" + host)
            status_code = req.status_code
            # Check the HTTP status code of the request
            if status_code == 401:
                # If there is an "unauthorised" code, try it against the wordlists
                self.weak_hosts[host] = [self.attempt_logon(host, status_code)]
            else:
                self.weak_hosts[host] = [status_code]
        except requests.exceptions.ConnectTimeout:  # If the host fails to connection
            self.weak_hosts[host] = ["Timeout"]
        except requests.exceptions.ConnectionError:  # If the host blocks the connection
            self.weak_hosts[host] = ["Error"]

    def attempt_logon(self, host, code):
        """
        Runs a brute force attack against the host using the username/password wordlists
        Returning a HTTP status code if it fails to login, or the list of credentials used if login is successful
        :param host: (str) The IP address of a device
        :param code: (srt) The HTTP code that resulted from the first login
        :return: (int) or (lst) Returns a HTTP status code or list of credentials
        """
        status_code = code
        # For each username, test every password
        for uname in self.user_list:
            for passwd in self.pass_list:
                try:
                    # Uses Basic HTTP authentication to test the credentials
                    ip = "http://" + str(uname) + ":" + str(passwd) + "@" + str(host)
                    credentials_req = requests.get(ip)
                    status_code = credentials_req.status_code
                    # If the login is successful, add the new status code to the dictionary
                    if status_code == 200:
                        return [status_code, uname, passwd]
                except requests.exceptions.ConnectTimeout:
                    continue
                except requests.exceptions.ConnectionError:
                    continue
        return status_code

    def get_codes_only(self):
        """
        Gets the values for each host IP address and their credentials
        :return: (lst) List of HTTP status codes and credentials
        """
        return self.weak_hosts.values()

    def get_weak_hosts(self):
        """
        Returns a list of all IP addresses that had weak credentials
        :return: (lst) A list of IP addresses
        """
        weak = []
        try:
            print(self.get_codes_only())
            for host in self.get_hosts_only():
                # Checks if the host had a successful login at all
                result = self.get_host_code(host)
                print(result)
                if result[0] == 200 or result[0][0] == 200:
                    weak.append(host)
        except TypeError:
            pass
        return weak

    def get_host_code(self, host):
        """
        Returns the HTTP code from the login attempt
        :param host: (str) The IP address of a device on the network
        :return: (int) The HTTP code
        """
        return self.weak_hosts.get(host)

    def get_weak_username(self, host):
        """
        Returns the username that was used to login to a device
        :param host: (str) The IP address of a given device
        :return: (str) The login username
        """
        try:
            username = self.weak_hosts.get(host)[0][1]
            return username
        except:
            return " "

    def get_weak_password(self, host):
        """
        Returns the password that was used to login to a device
        :param host: (str) The IP address of a given device
        :return: (str) The login password
        """
        try:
            password = self.weak_hosts.get(host)[0][2]
            return password
        except:
            return " "

    def get_total_weak_hosts(self):
        """
        Returns a count of how many hosts had a successful login
        :return: (int) The total count of weak hosts
        """
        return len(self.get_weak_hosts())