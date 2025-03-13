from math import prod
from param import *
from utils import *

class Header:

    # TODO Verify inputs (i.e. n, path, gamma must be a list even if only one block /!\)

    def __init__(self, n=None, alpha=None, beta=5*[None], gamma=None):
        """
        """
        self.n = n
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
    
    def __str__(self):
        return f"{[self.n] + [self.gamma] + self.beta} {10*' '} (alpha={self.alpha})"

    def generate(self, dest, path, x):
        # STEP 1: Compute all shared secret s
        if DEBUG: print(f"\nPath: {path[0].get_ip()} -> {path[1].get_ip()} -> {path[2].get_ip()} -> [{dest}] {10*' '} (x={x})")
        s, ss = [], [] # list of shared secret for encryption and integrity
        self.alpha = pow(G, x, MOD)
        for mixnode in path:
            alpha = pow(G, x, MOD)
            s.append([pow(key, x, MOD) for key in mixnode.get_encryption_key()])
            ss.append([pow(key, x, MOD) for key in mixnode.get_integrity_key()])
            b = exp_hash(alpha, s[-1], ss[-1][0])
            x = (x * b) % (MOD -1)

        # STEP 2: Preprocessing user input
        self.beta[1] = (s[1][3]*s[0][5]) % MOD
        self.beta[2] = (s[1][4]*s[0][6]) % MOD
        self.beta[3] = (s[1][5]) % MOD
        self.beta[4] = (s[1][6]) % MOD
        if DEBUG: print(f"Preprocessing mask : {self}")

        # STEP 3: Compute first round
        self.beta[0] = encrypt(dest, s[-1][0])
        self.n = path[-1].get_ip()
        self.gamma = compute_gamma(self.beta, ss[-1][0])
        if DEBUG: print("ENCRYPTION")
        if DEBUG: print(f"2) Encryption for {self.n} : {self}")

        # STEP 4: Encrypt each layer with s_i
        for i in [1,0]: # proceed in reverse order (s1 then s0)
            # last 2 blocks are truncated because they will be '1' ("zero-padding") thanks to the preprocessing step 
            self.beta = encrypt([self.n]+[self.gamma]+self.beta[:-2], s[i][:-2])
            self.gamma = compute_gamma(self.beta, ss[i][0])
            self.n = path[i].get_ip()
            if DEBUG: print(f"{i}) Encryption for {self.n} : {self}")
        
        return self
    
    def get_n(self):
        return self.n
    
    def get_alpha(self):
        return self.alpha
    
    def get_beta(self):
        return self.beta
    
    def get_gamma(self):
        return self.gamma