from mixnode import *
from header import *
from param import *
from tqdm import tqdm

ITERATIONS = 1000

for _ in range(NBR_MIXNODES):
    node = Mixnode()
    mixnodes[node.get_ip()] = node

for _ in tqdm(range(ITERATIONS)):
    dest = randint(1, MOD-1)
    path = sample([node for node in mixnodes.values()], 3)
    x = randint(1, MOD-2) # max "MOD-2" otherwise could get pow(G,x,MOD)==1

    header = Header().generate(dest, path, x)

    if DEBUG: print("DECRYPTION")
    for i in range(3):
        next_node = mixnodes[header.get_n()]
        header = next_node.process_packet(header)
        if DEBUG: print(f"{i}) Decryption from {next_node.get_ip()} : {header}")

    assert dest == header.get_n()

