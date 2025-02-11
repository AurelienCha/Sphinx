from random import seed
# seed(4)

NBR_MIXNODES = 10
NBR_TTP = 5

G = 7

PATH_LENGTH = 3 # Nbr of mixnodes in the path

# Nbr of blocks for different header parts
BETA_SIZE = 1 + 2 * (PATH_LENGTH - 1)
HEADER_SIZE = 2 + BETA_SIZE

BLOCK_SIZE = 8  # nbr bits per block

from sympy import prevprime
MOD = prevprime(pow(2, BLOCK_SIZE))
