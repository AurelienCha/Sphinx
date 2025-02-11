from mixnode import *
from TTP import *

class Mixnet:

    _instance = None  # SINGLETON
   
    def __new__(cls): 
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.mixnodes = {}  # Dict of mixnodes (key:node's IP, value: node)
            for _ in range(NBR_MIXNODES):
                cls._instance._add_mixnode()
            cls._instance.TTPs = []  # List of TTPs
            for _ in range(NBR_TTP):
                cls._instance._add_TTP()
        return cls._instance  

    def _add_mixnode(self):
        node = Mixnode()
        while len(self.mixnodes) and node.get_ip() in self.mixnodes.keys():
            node = Mixnode()
        self.mixnodes[node.get_ip()] = node

    def _add_TTP(self):
        self.TTPs.append(TTP())

    def get_mixnodes(self):
        return self.mixnodes

    def get_TTPs(self):
        return self.TTPs
