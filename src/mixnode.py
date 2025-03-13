from param import *
from utils import *
from random import randint
from header import *

class Mixnode:

    def __init__(self, ip=None):
        self.ip = ip if ip else self.generate_ip()
        # Encryption (s)
        self._sk_e = self.generate_key(size=7) # Secret key (Encryption)
        self.pk_e =  self.generate_public_key(self._sk_e) # Public key (Encryption)
        # Signature (s)
        self._sk_s = self.generate_key() # Secret key (Integrity)
        self.pk_s = self.generate_public_key(self._sk_s) # Public Key (Integrity)

    def process_packet(self, header): 
        """
        """
        alpha = header.get_alpha() # NOTE need an "alpha signature" ?
        beta = header.get_beta()
        gamma = header.get_gamma()

        # Step 1: Recompute share secrets
        s = [pow(alpha, sk, MOD) for sk in self._sk_e]
        ss = [pow(alpha, sk, MOD) for sk in self._sk_s][0] # SIGN

        # Step 2: Check integrity tag
        assert gamma == compute_gamma(beta, ss)

        # Step 3: Update alpha
        b = exp_hash(alpha, s, ss)
        alpha = pow(alpha, b, MOD)

        # Step 4: Decrypt beta
        beta += [1, 1]  # "zero-padding"
        beta = decrypt(beta, s)  # decryption
        n, gamma, *beta = beta  # extract new 'n' and 'gamma'

        # Step 5: Build new header
        return Header(n, alpha, beta, gamma)

    
    def generate_key(self, size=1):
        return [self._generate_key() for _ in range(size)]


    def _generate_key(self):
        sk = randint(1, MOD-1)
        if sk % 2 == 0: # Need to be 'odd'
            sk = (sk + 1) % MOD
        invalid = [0, (MOD-1)//2, ((MOD-1)//2)-2]
        if sk in invalid: # Choose a new key if invalid value
            return self._generate_key()
        else:
            return sk

    
    def generate_ip(self):
        ip = randint(1, MOD-1)
        if ip in [node.get_ip() for node in mixnodes.values()]:
            return self.generate_ip()
        return ip
    
    
    def generate_public_key(self, key):
        return [pow(G, sk, MOD) for sk in key]


    def get_encryption_key(self):
        return self.pk_e  # Public key (Encryption)

    def get_integrity_key(self):
        return self.pk_s  # Public key (Integrity)
    
    def get_ip(self):
        return self.ip
