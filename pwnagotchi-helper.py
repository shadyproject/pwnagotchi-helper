import os
import argparse
from fabric import Connection
import scapy.utils
import scapy.layers.dot11


def sick_logo():
    print('''
 _______                                                    __              __       __        ________                 __          
|       \                                                  |  \            |  \     |  \      |        \               |  \         
| $$$$$$$\__   __   __ _______   ______   ______   ______ _| $$_    _______| $$____  \$$       \$$$$$$$______   ______ | $$ _______ 
| $$__/ $|  \ |  \ |  |       \ |      \ /      \ /      |   $$ \  /       | $$    \|  \         | $$ /      \ /      \| $$/       \
| $$    $| $$ | $$ | $| $$$$$$$\ \$$$$$$|  $$$$$$|  $$$$$$\$$$$$$ |  $$$$$$| $$$$$$$| $$         | $$|  $$$$$$|  $$$$$$| $|  $$$$$$$
| $$$$$$$| $$ | $$ | $| $$  | $$/      $| $$  | $| $$  | $$| $$ __| $$     | $$  | $| $$         | $$| $$  | $| $$  | $| $$\$$    \ 
| $$     | $$_/ $$_/ $| $$  | $|  $$$$$$| $$__| $| $$__/ $$| $$|  | $$_____| $$  | $| $$         | $$| $$__/ $| $$__/ $| $$_\$$$$$$\
| $$      \$$   $$   $| $$  | $$\$$    $$\$$    $$\$$    $$ \$$  $$\$$     | $$  | $| $$         | $$ \$$    $$\$$    $| $|       $$
 \$$       \$$$$$\$$$$ \$$   \$$ \$$$$$$$_\$$$$$$$ \$$$$$$   \$$$$  \$$$$$$$\$$   \$$\$$          \$$  \$$$$$$  \$$$$$$ \$$\$$$$$$$ 
                                        |  \__| $$                                                                                  
                                         \$$    $$                                                                                  
                                          \$$$$$$                                                                                   
    ''')


def build_args():
    p = argparse.ArgumentParser()
    p.add_argument("host", help="ip address or hostname of the pwnagotchi")
    p.add_argument("-p", "--password", default="raspberry", help="password for pwnagotchi user")
    p.add_argument("-u", "--user", default="pi", help="pwnagotchi ssh user")
    p.add_argument("-d", "--handshake_dir",
                   default=os.path.join(os.path.abspath(os.getcwd()), "handshakes"),
                   help="Directory where handshakes will be copied and processed")
    return p


def transfer_handshakes(user, password, host, path):
    # todo: handle "authenticity of host cannot be established"
    print("Connecting to pwnagotchi")
    with Connection(f"{user}@{host}",
                    connect_kwargs={
                        "look_for_keys": False,
                        "password": password}) as c:
        pcap_dir = os.path.join(path, "pcap")
        pi_dir = f"/home/{user}/handshakes"
        c.run(f"rm -rf {pi_dir}")
        print("Copying handshakes from /root/handshakes")
        c.run(f"sudo cp -r /root/handshakes {pi_dir}", pty=True)

        os.mkdir(pcap_dir)

        print("Downloading pcaps")
        c.get(f"{pi_dir}/*", pcap_dir)


# try to do this natively instead of spawning a subprocess to run aircrack-ng
# todo determine if this actually matches the first bssid returned by aircrack-ng
def extract_first_bssid(pcap):
    packets = scapy.utils.rdpcap(pcap)

    for p in packets:
        if p.hasLayer(scapy.layers.dot11.Dot11):
            if p.type == 0 and p.subtype == 8:  # management frame
                bssid = p[scapy.layers.dot11.Dot11].addr3
                return bssid

    return None


def ssid_from_filename(filename):
    pos = filename.rfind('_')
    ssid = filename[pos, len(filename)]
    return ssid


def extract_bssids(pcap_dir):
    bssids = {}
    for file in os.scandir(pcap_dir):
        network_name = ssid_from_filename(file.name)
        bssid = extract_first_bssid(file.path)
        if bssid is not None:
            bssids[network_name] = bssid
    return bssids


if __name__ == "__main__":
    sick_logo()
    parser = build_args()
    args = parser.parse_args()

    transfer_handshakes(args.user, args.password, args.host, args.handshake_dir)  # type: ignore
    bssid_list = extract_bssids(os.path.join(args.handshake_dir, 'pcap'))  # type: ignore
