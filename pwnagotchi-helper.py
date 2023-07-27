import os
import argparse
from fabric import Connection
import scapy.utils
import scapy.layers.dot11 as wifi
import shutil

PCAP_DIR = "pcap"
PMKID_DIR = "pmkid"
HCCAP_DIR = "hccapx"
HANDSHAKE_DIR = "handshakes"


def sick_logo():
    print(
        """
 ____  ____  ____  ____  ____  ____  ____  ____  ____  ____ 
||P ||||w ||||n ||||a ||||g ||||o ||||t ||||c ||||h ||||i ||
||__||||__||||__||||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____                         
||H ||||e ||||l ||||p ||||e ||||r ||                        
||__||||__||||__||||__||||__||||__||                        
|/__\||/__\||/__\||/__\||/__\||/__\|                        
    """
    )


def build_args():
    p = argparse.ArgumentParser()
    p.add_argument("host", help="ip address or hostname of the pwnagotchi")
    p.add_argument(
        "-p", "--password", default="raspberry", help="password for pwnagotchi user"
    )
    p.add_argument("-u", "--user", default="pi", help="pwnagotchi ssh user")
    p.add_argument(
        "-d",
        "--handshake_dir",
        default=os.path.join(os.path.abspath(os.getcwd()), HANDSHAKE_DIR),
        help="Directory where handshakes will be copied and processed",
    )
    return p


def setup_directories(base_dir):
    if os.path.exists(base_dir):
        shutil.rmtree(os.path.join(base_dir, PMKID_DIR))
        shutil.rmtree(os.path.join(base_dir, HCCAP_DIR))
        shutil.rmtree(os.path.join(base_dir, PCAP_DIR))
        os.rmdir(base_dir)

    os.makedirs(os.path.join(base_dir, PCAP_DIR))
    os.makedirs(os.path.join(base_dir, PMKID_DIR))
    os.makedirs(os.path.join(base_dir, HCCAP_DIR))


def transfer_handshakes(user, password, host, path):
    # todo: handle "authenticity of host cannot be established"
    # todo: handle actual passphrase for a locked keychain/private key
    print("Connecting to pwnagotchi")
    pcap_dir = os.path.join(path, PCAP_DIR)
    pi_home = f"/home/{user}"
    pi_handshakes = f"{pi_home}/{HANDSHAKE_DIR}"
    with Connection(
        f"{user}@{host}", connect_kwargs={"look_for_keys": False, "password": password}
    ) as c:
        c.run(f"sudo rm -rf {pi_handshakes}", pty=True)
        print("Copying handshakes from /root/handshakes")
        c.run(f"sudo cp -r /root/handshakes {pi_home}", pty=True)
        print("Downloading pcaps")
        with c.sftp() as s:
            s.chdir(pi_handshakes)
            for f in s.listdir():
                print(f"Downloading {f}")
                s.get(f"{pi_handshakes}/{f}", os.path.join(pcap_dir, f))


# do this natively instead of spawning a subprocess to run aircrack-ng
def extract_first_bssid(pcap):
    packets = scapy.utils.rdpcap(pcap)

    for p in packets:
        if p.haslayer(wifi.Dot11):
            if p.type == 0 and p.subtype == 8:  # management frame
                bssid = p[wifi.Dot11].addr3
                return bssid

    return None


def ssid_from_filename(filename):
    pos = filename.rfind("_")
    ssid = filename[0:pos]
    return ssid


def extract_pmkid(packet):
    # Check if the packet contains 802.11 (Wi-Fi) layer and the required fields
    if (
        packet.haslayer(wifi.Dot11)
        and packet.haslayer(wifi.Dot11.Dot11AssoReq)
        and packet.haslayer(wifi.Dot11AssoResp)
    ):
        # Check if the packet contains the PMKID field (tag type 5)
        if (
            5 in packet[wifi.Dot11AssoReq].tagpresent
            or 5 in packet[wifi.Dot11AssoResp].tagpresent
        ):
            # Extract the PMKID value
            pmkid = (
                packet[wifi.Dot11AssoReq].pmkidlist[0]
                if 5 in packet[wifi.Dot11AssoReq].tagpresent
                else packet[wifi.Dot11AssoResp].pmdklist[0]
            )
            return pmkid
    return None


def convert_to_pkmid(pcap_file):
    print(f"looking for pkmid in {pcap_file}")
    packets = scapy.utils.rdpcap(pcap_file)
    for p in packets:
        pmkid = extract_pmkid(p)
        if pmkid is not None:
            print(f"Found pkmid {pmkid} in {pcap_file}")
            return True
    return False


def convert_to_handshake(pcap_file):
    print(f"Looking for handshake in {pcap_file}")
    return False


def convert_file(pcap):
    # first try to convert to pmkid
    if not convert_to_pkmid(pcap):
        # then try to find a handshake
        if not convert_to_handshake(pcap):
            return False
    return True


def extract_bssids(pcap_dir):
    bssids = {}
    for file in os.scandir(pcap_dir):
        network_name = ssid_from_filename(file.name)
        bssid = extract_first_bssid(file.path)
        convert_file(file.path)
        if bssid is not None:
            bssids[network_name] = bssid
    return bssids


if __name__ == "__main__":
    parser = build_args()
    args = parser.parse_args()

    sick_logo()
    setup_directories(args.handshake_dir)
    transfer_handshakes(args.user, args.password, args.host, args.handshake_dir)  # type: ignore
    bssid_list = extract_bssids(os.path.join(args.handshake_dir, PCAP_DIR))  # type: ignore
    print(bssid_list)
