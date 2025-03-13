from param import *
from random import randint, sample
from math import prod


def compute_gamma(beta, ss): 
    """
    RSA encryption 
    TODO: ELGAMAL Version
    :param ss: Shared Sign ('e' in RSA notation)
    """
    gamma = 1
    for beta_i in beta:
        gamma = (gamma * pow(beta_i, ss, MOD)) % MOD
    # NOTE same as ? : prod([pow(beta_i, ss, MOD) for beta_i in beta]) % MOD
    return gamma

def exp_hash(alpha, s, ss): 
    # NOTE a*a*s or s*s*a ? 
    s = prod(s) % MOD # NOTE prod() or sum() ? (MOD) or (MOD-1) ? 
    #-> prod() with (MOD) => BALANCED & size = MOD => best option
    #-> sum() with (MOD) => UNBALANCED & size = MOD
    #-> prod() with (MOD-1) => BALANCED & size = MOD/2
    #-> sum() with (MOD-1) => BALANCED & size = MOD/2
    
    return (alpha * s * ss) % (MOD - 1) # (MOD - 1) because value is in exponent /!\

def decrypt(message, key):
    assert len(message)==len(key), "decryption impossible"
    return [(m * k) % MOD for (m, k) in zip(message, key)]

def encrypt(message, key):
    if isinstance(message, int) and isinstance(key, int):
        return (message * pow(key, -1, MOD)) % MOD
    assert len(message)==len(key), "encryption impossible"
    return [(m * pow(k, -1, MOD)) % MOD for (m, k) in zip(message, key)]    



# def generate(size=None):
#     if size is None:
#         return randint(1, MOD-1) # MOD-1
#     return [randint(1, MOD-1) for _ in range(size)] # MOD-1

# def split_secret(secret, m):
#     if isinstance(secret, int):
#         shares = [choice(odds) for _ in  range(m-1)]
#         last_share = (secret * prod([pow(x, -1, MOD) for x in shares])) % MOD
#         shares.append(last_share)
#         assert secret == prod(shares) % MOD
#         return shares
#     size = len(secret)
#     shares = [[choice(odds) for _ in range(size)] for _ in  range(m-1)]
#     last_share = [((s * prod([pow(x, -1, MOD) for x in x_list])) % MOD) for (s, *x_list) in zip(secret, *shares)]
#     shares += [last_share]
#     assert secret == [prod(x_list) % MOD for x_list in zip(*shares)]
#     return shares