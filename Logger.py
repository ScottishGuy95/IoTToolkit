#!/usr/bin/env python3
"""
Handles writing scan results to a file
"""

__author__ = "ScottishGuy95"
__license__ = "MIT"


import os
import platform
from datetime import datetime
import time


def get_current_time():
    """
    Returns the current time in Hour:Minute:Seconds format
    :return: (str) Current time
    """
    return datetime.now().strftime("%H:%M:%S")


def manage_scan_directory():
    """
    Creates a directory for storing the scan results and returns its filepath
    :return: (str) The filepath of the scanLogs directory
    """
    # Checks the devices operating system and creates a formatted String
    if platform.system() == "Windows":
        scan_dir = "\\scanLogs\\"
    else:
        scan_dir = "/scanLogs/"
    # Checks if the directory already exists
    if 'scanLogs' not in os.listdir(os.getcwd()):
        # Takes the current files path and adds the directory string to create the new directory here
        os.mkdir(os.path.join(os.getcwd() + scan_dir))
    # Returns the newly created directory
    return os.path.join(os.getcwd() + scan_dir)


class Logger:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")   # Gets local date + time
        self.path = manage_scan_directory()                         # Checks if the scanLogs dir exists and returns path
        self.name = self.path + "scan_" + str(self.timestamp) + ".txt"  # Sets file name
        self.start_time = time.time()
        file = open(self.name, "x")                                 # Creates the scan log text file
        # Writes some header data to the text file
        file.write("IoT Toolkit - Security Scan")
        file.write("\nDate = " + datetime.today().strftime("%d/%m/%y"))
        file.write("\nStart Time = " + get_current_time())
        file.write("\n")

    def get_filename(self):
        """
        Returns the filename of the current scan log text file
        :return: (str) The filename of the text file
        """
        return os.path.abspath(self.name)

    def write_to_file(self, data):
        """
        Takes a string of data to add to the text file
        :param data: (str) The data that is to be added
        """
        file = open(self.name, "a", encoding='utf-8')
        file.write("\n" + data)

    def end(self):
        """
        Used to add the final values to the end of the log file
        """
        file = open(self.name, "a")
        file.write("\nEnd Time = " + get_current_time())
        file.write("\nToolkit Duration = " + str(self.get_scan_time()) + "s")
        file.write("\nEnd of scan log")
        file.close()

    def get_scan_time(self):
        """
        Gets the duration from now since the object was created
        Used to get the total duration of the Logger in seconds
        :return: (str) The duration of the Loggers operations in seconds
        """
        return str(round(time.time() - self.start_time))
