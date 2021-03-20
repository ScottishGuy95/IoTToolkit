#!/usr/bin/env python3
"""
Contains the mitigation methods that are displayed to the user upon scan completion
Displays messages depending on scan results (port scan message if the port scan found ports)
"""

__author__ = "ScottishGuy95"
__license__ = "MIT"

import random


class Mitigations:
    def __init__(self):
        self.port = ["Network Port:\nA network port is a way for data to enter or leave your device. For each device, "
                     "they cover 2 different methods of handling the data (the protocol), called TCP or UDP. For each"
                     "of these protocols, there can be up to 65,535 ports to cover. Ports are an essential part of your"
                     " device, and without them, your device could not contact anything.",
                     "Open ports are not always a security risk but can be exploited by malicious actors who take "
                     "advantage of security issues, such as weak credentials or vulnerabilities in programs on your "
                     "device. ",
                     "If your scan resulted in open ports, check what service they are associated with to try judge "
                     "if they are malicious or not. Check if you recognise the service name from a program on your "
                     "computer that is used by you.",
                     "If there is a service name missing or you are unsure what it means, google the port number and "
                     "service name to try and see what it is and if it is a known security risk port that you do not "
                     "need left open on your device.",
                     "A couple common insecure ports that you should be cautious of unless you know they are "
                     "required; Port 22, 21 - FTP, Port 23 - TELNET, Port 3389 - Remote Desktop. "]

        self.credentials = ["Credentials:\nCredentials are the usernames, emails, and passwords you use to login to "
                            "services, websites of devices. Malicious actors have lists of common or well-known "
                            "passwords that are used in IoT devices you purchase and can use them to access your "
                            "device.",
                            "When you buy a new device, always check what the username and password are before use. "
                            "You should always then use the devices documentation or guides to change the username "
                            "and/or password to something more secure.",
                            "Make use of strong unique passwords when creating passwords. Passwords like "
                            "‘password123’ or ‘football’ are not secure and malicious actors already know them.",
                            "Passwords should make use of the ‘3 random words’ technique. Pick 3 completely random "
                            "words, stick them together and use that - ‘orangebearcar’ - for example.",
                            "Make sure you use unique passwords for different devices and accounts you make. Using "
                            "the same password for multiple devices/accounts can put them at risk if one account gets "
                            "breached."]
        self.encryption = ["Encryption:\nEncryption is a way of altering the data your device sends so that only "
                           "those who should read the data can read the data. The data is scrambled into "
                           "unintelligible text, until it reaches its final destination, where it is converted back "
                           "to readable text e.g., Security > 2hewe$BU > Security",
                           "Research your IoT device, look into what options you can enable or adjust to enable "
                           "encryption. This could be from documentation, guides, or online searches.",
                           "If encryption is not an option, try turn off features that access the internet that are "
                           "not needed. This can help mitigate the possible issues your device could run into online.",
                           "Look online into how to put your IoT devices and other vulnerable devices on their own "
                           "network in your home. Keep one network with devices that handle your private, "
                           "sensitive information and the other for less private devices.",
                           ""]
        self.general = ["Always ensure your computer and its programs are up to date. To help with this, "
                        "turn on features like ‘Automatic Updates’ that can download and install these updates for "
                        "you automatically.",
                        "Make sure you have a computer with an Anti-Virus program installed. An Anti-Virus program "
                        "can help protect viruses from getting into your computer.",
                        "Always make use of two-factor authentication or multi-factor authentication when offered, "
                        "as it can help you protect your account if a malicious actor gets into one of your accounts.",
                        "Don’t open any links from emails you are not expecting. Always check the sender address and "
                        "hover over links before to check if the link goes where it says it goes.",
                        "Back up the data on your device regularly to protect them. Your data could be lost from a "
                        "virus, physical damage or by malicious actors."]

    def get_port_desc(self):
        """
        Gets the description of a network port from the network port list
        :return: (str) Explanation of what a network port is, first element
        """
        return self.port[0]

    def get_credentials_desc(self):
        """
        Gets the description of a what Credentials are from the credentials list
        This will always be the first element in the list
        :return: (str) Explanation of what credentials are
        """
        return self.credentials[0]

    def get_encryption_desc(self):
        """
        Gets the description of what encryption is, from the encryption list
        This will always be the first element in the list
        :return: (str) Explanation of what encryption is
        """
        return self.encryption[0]

    def get_random_messages(self, option):
        """
        Takes a string, and pulls random messages from the list that matches the given string
        :param option: (str) The type of mitigation methods needed
        :return: (lst) A list of 2 elements, randomly selected from a list of data
        """
        if option == 'port':
            # Returns 2 random list elements from the first element onwards
            return random.sample(self.port[1:], k=2)
        elif option == 'credentials':
            return random.sample(self.credentials[1:], k=2)
        elif option == 'encryption':
            return random.sample(self.encryption[1:], k=2)
        else:
            return random.sample(self.general, k=2)
