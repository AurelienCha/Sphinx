from param import *
from math import prod
from utils import *

class Header:

    # TODO Verify inputs (i.e. n, path, gamma must be a list even if only one block /!\)

    def __init__(self, *, n = 0, gamma = 0, beta =  [0] * BETA_SIZE, alpha = None):
        """
        Mixnet packet header (header = [n, gamma, beta])
        """
        self.n = n
        self.gamma = gamma
        self.beta = beta
        self.alpha = alpha

    def get_alpha(self):
        return self.alpha
    def get_n(self):
        if isinstance(self.n, list):
            return self.n
        return self.n
    def get_gamma(self):
        return self.gamma
    def get_beta(self):
        return self.beta

    def __add__(self, header): # TODO NOT WORKING
        if not isinstance(header, Header):
            raise TypeError("Can only add two Header objects")
        n = (self.n * header.get_n()) % MOD
        gamma = (self.gamma * header.get_gamma()) % MOD
        beta = [(b * b_) % MOD for b, b_ in zip(self.beta, header.get_beta())]
        alpha = self.alpha
        return Header(n=n, gamma=gamma, beta=beta, alpha=alpha)
        # reduce(lambda a,b: a+b, xes)

    def __repr__(self):
        return f"{self.n} | {self.gamma} | {self.beta} (alpha={self.alpha})"

    def decrypt(self, shared_secret, shared_sign): # TODO
        """
        Decrypt one layer of the header 

        :param shared_secret: Shared secrets used for encryption (encryption)
        :param shared_sign: Shared secrets used for integrity (integrity)
        """
        print(shared_secret, shared_sign)
        self._verify_integrity(shared_sign)
        self.beta += [1,1] # "zero-padding" ('one' because modular multiplication)
        header = self._uncombine(shared_secret)
        self.n = header[0]
        self.gamma = header[1]
        self.beta = header[2:]

        # TODO handle self.alpha
        a0 = pow(self.alpha[0], custom_hash(self.alpha[0], sum(shared_secret)), MOD)
        a1 = pow(self.alpha[1], custom_hash(self.alpha[1], shared_sign), MOD)
        self.alpha = (a0, a1)


    def generate(self, ip, path, shared_secrets, shared_signs, alpha):
        """
        Generates mixnet packet header.
        
        :param ip: User input (int)
        :param path: List of mixnode of the path (list of int) # TODO not mixnode list but ip list
        :param shared_secrets: List of shared secrets used for encryption (encryption)
        :param shared_signs: List of shared secrets used for integrity (integrity)
        :param alpha: ...
        """
        self.alpha = alpha
        self._preprocessing(ip, shared_secrets)
        # header is constructed in reverse order from the path
        print(shared_signs)
        self._first_round(path[-1], shared_signs[-1])
        # Iterate through shared secrets in reverse order 
        # while ignoring last element that was already handled in _first_round()
        print(self)
        for i in range(-2, -len(shared_secrets)-1, -1): 
            # i = Index of the round (negative since in reverse order: [-2] -> [-3] -> ...)
            self._round_i(path[i], shared_secrets[i], shared_signs[i])
            print(self)


    def _preprocessing(self, ip, shared_secrets):
        """
        ARTICLE: Compute PHI and combine it with the initial input
        I.E. Generate self.beta for the first round

                                 ╔════════╗                                                                   
        ┌────────────────────────║   IP   ║                                                                   
        |                        ╚════════╝                                                                   
        |                        ╔════════╗─────────────────────────────────────────────────────┐             
        ⨁ <──────────────────── ║  s2[0] ║░░░░░░░░|░░░░░░░░|░░░░░░░░|░░░░░░░░|░░░░░░░░|░░░░░░░░|             
        |                        ╚════════╝─────────────────────────────────────────────────────┘             
        |      ┌──────────────────────────╔═══════════════════════════════════╗                              
        ⨁ <── |░░░░░░░░|░░░░░░░░|░░░░░░░░║ s1[-4] | s1[-3] | s1[-2] | s1[-1] ║                              
        |      └──────────────────────────╚═══════════════════════════════════╝                              
        |      ┌──────────────────────────╔═════════════════╗─────────────────┐                              
        ⨁ <── |░░░░░░░░|░░░░░░░░|░░░░░░░░║ s0[-4] | s0[-3] ║░░░░░░░░|░░░░░░░░|                              
        |      └──────────────────────────╚═════════════════╝─────────────────┘                              
        |                        ╔════════════════════════════════════════════╗                              
        └──────────────────────> ║  β2[0] |  β2[1] |  β2[2] |  β2[3] |  β2[4] ║                              
                                 ╚════════════════════════════════════════════╝   

        :param ip: User input (int)
        :param s: List of shared secrets (encryption)
        """                     
        # S3 Calculations
        self.beta[0] = (ip * shared_secrets[-1][0]) % MOD 
        # Phi Calculations (Modular Inverses)
        for i in range(-1, -BETA_SIZE, -1):
            phi = prod([shared_secrets[j-1][k] for j in range(-1, -len(shared_secrets), -1) if (k:=i-(j+1)*2) < 0])
            self.beta[i] = pow(phi, -1, MOD)


    def _first_round(self, last_n, last_shared_sign):
        """
        Construct the first round of the header construction (/!\ processed in reverse order)
        I.E. Generate self.n and self.gamma for the first round (self.beta already computed in _preprocessing())

                  ╔════════════════════════════════════════════╗                              
                  ║  β2[0] |  β2[1] |  β2[2] |  β2[3] |  β2[4] ║                              
                  ╚════════════════════════════════════════════╝                              
                                         |                                                   
        ╔══╗                             |                                                   
        ║s2║ ────────────> [ RSA ] <─────┴────────────────┐                                  
        ╚══╝                  |                           |                                  
                              v                           v                                  
                ╔════════╦════════╦════════════════════════════════════════════╗            
                ║   n2   ║   γ2   ║  β2[0] |  β2[1] |  β2[2] |  β2[3] |  β2[4] ║            
                ╚════════╩════════╩════════════════════════════════════════════╝   
        
        :param last_n: last mixnode IP in the path
        :param last_shared_sign: last shared secret used for integrity
        """  
        self.n = last_n
        self.gamma = self._compute_gamma(last_shared_sign)


    def _round_i(self, n, shared_secret, shared_sign):
        """
        Generates mixnet packet header.

                ╔════════╦════════╦════════════════════════════════════════════╗            
         ┌───── ║   n2   ║   γ2   ║  β2[0] |  β2[1] |  β2[2] |  β2[3] |  β2[4] ║            
         |      ╚════════╩════════╩════════════════════════════════════════════╝            
         |      ╔══════════════════════════════════════════════════════════════╗            
         ⨁ <── ║  s1[0] |  s1[1] |  s1[2] |  s1[3] |  s1[4] |  s1[5] |  s1[6] ║            
         |      ╚══════════════════════════════════════════════════════════════╝            
         |      ╔════════════════════════════════════════════╗─────────────────┐            
         └────> ║  β1[0] |  β1[1] |  β1[2] |  β1[3] |  β1[4] ║    1   |    1   |            
                ╚════════════════════════════════════════════╝─────────────────┘            
                                        |                                                   
        ╔══╗                            |                                                   
        ║s1║ ───────────> [ RSA ] <─────┴────────────────┐                                  
        ╚══╝                 |                           |                                  
                             v                           v                                  
                ╔════════╦════════╦════════════════════════════════════════════╗            
                ║   n1   ║   γ1   ║  β1[0] |  β1[1] |  β1[2] |  β1[3] |  β1[4] ║            
                ╚════════╩════════╩════════════════════════════════════════════╝   
        
        :param n: Mixnode IP
        :param shared_secret: Shared secrets used for encryption (encryption)
        :param shared_sign: Shared secrets used for integrity (integrity)
        """
        self.beta = self._combine(shared_secret)[:-2]
        self.gamma = self._compute_gamma(shared_sign)
        self.n = n


    def _compute_gamma(self, e): # TODO doc string
        """
        RSA encryption 
        TODO: ELGAMAL Version
        :param e: Shared Sign ('e' to keep RSA notation)
        """
        gamma = 1
        for m in self.beta:
            gamma = (gamma * pow(m, e, MOD)) % MOD
        return gamma

    def _verify_integrity(self, shared_sign): # TODO doc string
        assert self.gamma == self._compute_gamma(shared_sign)


    def _combine(self, shared_secret): # TODO doc stirng
        """
        COMBINE header WITH shared secret ...
        """
        return [(h * s) % (MOD) for (h, s) in zip([self.n] + [self.gamma] + self.beta, shared_secret)]


    def _uncombine(self, shared_secret): # TODO
        return [(b * pow(s, -1, MOD)) % (MOD) for (b, s) in zip(self.beta, shared_secret)]                        
        