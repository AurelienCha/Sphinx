from param import *
from random import randint
from math import prod

def custom_hash(x, s): # TODO OPTIMMIZE and crypto hash (not python hash)
    return hash((x, s)) % (MOD-1)

def generate(size=None):
    if size is None:
        return randint(1, MOD-1)
    return [randint(1, MOD-1) for _ in range(size)]

def exp(x, g=G):
    if isinstance(x, int):
        return pow(g, x, MOD)
    elif isinstance(x, list):
        return [exp(_, g) for _ in x]
    else:
        raise "ERROR exp"

def split_secret(secret, m):
    if isinstance(secret, int):
        shares = [randint(1, MOD-1) for _ in  range(m-1)]
        last_share = (secret * prod([pow(x, -1, MOD) for x in shares])) % MOD
        shares.append(last_share)
        assert secret == prod(shares) % MOD
        return shares
    size = len(secret)
    shares = [[randint(1, MOD-1) for _ in range(size)] for _ in  range(m-1)]
    last_share = [((s * prod([pow(x, -1, MOD) for x in x_list])) % MOD) for (s, *x_list) in zip(secret, *shares)]
    shares += [last_share]
    assert secret == [prod(x_list) % MOD for x_list in zip(*shares)]
    return shares