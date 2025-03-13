from sympy import prevprime

DEBUG = False
mixnodes = {}

NBR_MIXNODES = 10
NBR_TTP = 9

BLOCK_SIZE = 8  # nbr bits per block
MOD = 227 # prevprime(pow(2, BLOCK_SIZE))
G = 6 # find_generator(MOD)

def find_generator(p, min_=3):
    for g in range(min_,p+1):
        start = g
        x = start
        for i in range(p-1):
            x = (x * g) % p
            if x == start:
                if i == p-2:
                    return g
                else:
                    break