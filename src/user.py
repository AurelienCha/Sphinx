from random import randint, sample
from header import *
from param import *

class User:

    def __init__():
        pass # TODO

    def send_packet(self, dest, path=None, x=None):

        path = path if path else sample(mixnodes, 3)
        x = x if x else randint(1, MOD-1)

        header = Header().generate(dest, path, x)
        return header

    def share_values(self):
        pass # TODO

