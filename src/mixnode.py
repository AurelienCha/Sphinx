from param import *
from utils import *
from random import randint

class Mixnode:

    def __init__(self):
        self.ip = generate()
        self._sk_e = generate(HEADER_SIZE)  # Secret key (Encryption)
        self.pk_e =  exp(self._sk_e) # Public key (Encryption)
        self._sk_s = generate() # Secret key (Integrity)
        self.pk_s = exp(self._sk_s) # Public Key (Integrity)
        self.queue = []  # List of packets (i.e. headers) # TODO not used


    def get_ip(self):
        """
        :return id: Return the ID of the mixnode (i.e. IP address simulated by a randint)
        """
        return self.ip

    def get_encryption_key(self):
        """
        :return self.pk_e: Get the Public key (Encryption)
        """
        return self.pk_e

    def get_integrity_key(self):
        """
        :return self.pk_s: Get the Public key (Integrity)
        """
        return self.pk_s

    def process_packet(self, header):  # TODO docstring
        """
        :param header: 
        """     
        (alpha_encr, alpha_sign) = header.get_alpha()
        shared_secret = exp(self._sk_e, g=alpha_encr)
        shared_sign = exp(self._sk_s, g=alpha_sign)
        header.decrypt(shared_secret, shared_sign)
        
        return header


