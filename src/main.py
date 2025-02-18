from mixnet import *
from user import *
from utils import *

from tqdm import tqdm

ITERATIONS = 1
progress_bar = tqdm(range(ITERATIONS))
size = len(str(MOD))

for _ in progress_bar:
    mixnet = Mixnet()
    mixnodes = mixnet.get_mixnodes()
    TTPS = mixnet.get_TTPs()

    user = User()
    ip = generate()
    progress_bar.set_description(f"IP = {ip:>{size}}")
    header = user.send_packet(ip)

    while ip != (next_ip := header.get_n()):
        next_node = mixnodes[next_ip]
        header = next_node.process_packet(header)
    print(f"\nSENDING IP: {ip}\nFINAL IP: {next_ip}\n")
    assert next_ip == ip


