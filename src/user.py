from header import *
from mixnet import *
from utils import *
from uuid import uuid4
from random import randint, sample
from hashlib import sha256
from functools import reduce

class User:

    def __init__(self):
        mixnet = Mixnet()  # Mixnet is a Singleton
        self.mixnodes = mixnet.get_mixnodes()
        self.TTPs = mixnet.get_TTPs()
        self.id = uuid4()

    def _random_path(self, length=3):
        return sample(list(self.mixnodes.values()), length)

    def _share_secrets(self, path):
        nounce = generate()
        x = nounce
        shared_values = []

        for node in path:
            if x == 0: # Invalid value -> regenrate a random value
                return self._share_secrets(path)
            shared_value = []
            for node_pk in node.get_encryption_key():
                s = exp(x, g=node_pk)
                shared_value.append(s)
            x = (x * custom_hash(exp(x), sum(shared_value))) % (MOD - 1)
            shared_values.append(shared_value)

        return (exp(nounce), shared_values)
       
    def _share_signs(self, path):
        nounce = generate()
        x = nounce
        shared_values = []

        for node in path:
            if x == 0: # Invalid value -> regenrate a random value
                return self._share_signs(path)
            shared_value = exp(x, g=node.get_integrity_key())
            x = (x * custom_hash(exp(x), shared_value)) % (MOD - 1)
            shared_values.append(shared_value)
        
        return (exp(nounce), shared_values)

    def send_packet(self, ip):
        path = self._random_path()
        (alpha_0, shared_secrets) = self._share_secrets(path)
        (alpha_1, shared_signs) = self._share_signs(path)
        alpha = (alpha_0, alpha_1)
        path = [p.get_ip() for p in path]

        TTP_ip = split_secret(ip, NBR_TTP)
        TTP_path = split_secret(path, NBR_TTP)
        TTP_shared_secrets__ = [split_secret(s, NBR_TTP) for s in shared_secrets]
        TTP_shared_secrets = [[TTP_shared_secrets__[j][i] for j in range(len(shared_secrets))] for i in range(NBR_TTP)]

        partial_headers = [Header() for i in range(NBR_TTP)]
        for i in range(NBR_TTP):
            partial_headers[i].generate(TTP_ip[i], TTP_path[i], TTP_shared_secrets[i], shared_signs, alpha)
        return reduce(lambda a,b: a+b, partial_headers)
        # """
        # h = Header(ip, path, shared_secrets, shared_signs, alpha)
        # return h