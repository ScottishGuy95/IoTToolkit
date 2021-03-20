#!/usr/bin/env python3
"""
Parent class of all classes that will test credentials
"""

__author__ = "ScottishGuy95"
__license__ = "MIT"

import platform
import threading
import sys
import time
from queue import Queue


def get_os():
    """
    Checks the OS of the system running and alters the directory structure accordingly
    :return: The directory location of the Wordlists folder
    """
    if platform.system() == "Windows":
        wordlist_dir = "Wordlists\\"
    else:
        wordlist_dir = "Wordlists/"
    return wordlist_dir


def load_wordlist(list_name):
    """
    Takes the location of a wordlist file and loads it into a lst
    :param list_name: (str) The name of the wordlist file to load
    :return: (lst) A list containing the files lines
    """
    try:
        with open(list_name) as f:
            f_contents = f.readlines()
    except IOError:
        print('Error when trying to open the file: %s' % list_name)
        print('Exiting the program as the required Wordlists directory is not available')
        sys.exit()
    data = [word.strip() for word in f_contents]
    return data


class Credentials:
    def __init__(self):
        self.start_time = time.time()
        self.weak_hosts = {}
        self.wordlist_loc = get_os()
        self.user_list_name = self.wordlist_loc + "usernamesMIRAI.txt"
        self.pass_list_name = self.wordlist_loc + "passwordsMIRAI.txt"
        self.user_list = load_wordlist(self.user_list_name)
        self.pass_list = load_wordlist(self.pass_list_name)
        self.scans = Queue()
        self.current_host = ''
        self.current_user = ''

    def get_hosts_only(self):
        """
        Gets all of the host IP addresses that were scanned
        :return: (lst) List of IP addresses
        """
        return self.weak_hosts.keys()

    def attempt_login(self, password):
        """
        Used to brute force logins. This method is overridden by each child class
        :param password: (str) Password used to test the login
        """
        pass

    def threader(self):
        """
        Takes each password and passes it to the scanner function
        """
        while True:
            worker = self.scans.get()
            self.attempt_login(worker)
            self.scans.task_done()

    def start_threads(self):
        """
        Creates and manages the threads that help improve the scanning speed
        """
        try:
            for x in range(5):
                # Call the threader, then class them as daemon, to ensure program does not end until threads are done
                t = threading.Thread(target=self.threader)
                t.daemon = True
                t.start()
        except RuntimeError:
            pass

        # For each password, available, pass it to our Queue object scans
        # Wait until all workers are done, ensuring all processes are complete before continuing .join
        for worker in self.pass_list:
            self.scans.put(worker)
        self.scans.join()

    def start_scan(self, host, name):
        """
        Used to pass variables and begin the credential scanner
        :param host: (str) The IP address of a device
        :param name: (str) The username being used to test the scanner
        """
        self.current_host = host
        self.current_user = name
        self.start_threads()
        with self.scans.mutex:
            self.scans.queue.clear()

    def get_scan_time(self):
        """
        Gets the duration from now since the object was created
        Used to get the total duration of the Credentials operations in seconds
        :return: (str) The duration in seconds
        """
        return str(round(time.time() - self.start_time))
