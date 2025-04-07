import os
import argparse
from fabric import Connection
import scapy.utils
import scapy.layers.dot11 as wifi
import scapy.layers.eap as eap
import shutil

PCAP_DIR = "pcap"
HANDSHAKE_DIR = "handshakes"
HASHCAT_DIR = "hashcat"


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
    p.add_argument("host", help="ip address or hostname of the pwnagotchi", nargs="?")
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
    p.add_argument(
        "--local-only",
        action="store_true",
        help="Skip SSH transfer and only process pcap files in the handshake directory",
    )
    return p


def setup_directories(base_dir, clean=True):
    if clean:
        if os.path.exists(base_dir):
            shutil.rmtree(os.path.join(base_dir, PCAP_DIR))
            shutil.rmtree(os.path.join(base_dir, HASHCAT_DIR))
            os.rmdir(base_dir)

        os.makedirs(os.path.join(base_dir, PCAP_DIR))
        os.makedirs(os.path.join(base_dir, HASHCAT_DIR))
    else:
        # Just ensure directories exist without cleaning
        os.makedirs(os.path.join(base_dir, PCAP_DIR), exist_ok=True)
        os.makedirs(os.path.join(base_dir, HASHCAT_DIR), exist_ok=True)


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


def extract_pmkid(packet):
    # Check if the packet contains 802.11 (Wi-Fi) layer and the required fields
    if packet.haslayer(wifi.Dot11) and packet.haslayer(eap.EAPOL):
        eapol_raw = bytes(packet[eap.EAPOL])
        # EAPOL frame must be at least 121 bytes for PMKID
        if len(eapol_raw) < 121:
            return None

        # Check if it's EAPOL-Key frame (type = 3)
        if eapol_raw[1] != 3:
            return None

        # Check Key Information bits for right message type
        # 0x8a = Message 1: 10001010 (pairwise=1, install=0, ack=1, mic=0, secure=1, error=0, request=1, encrypted=0)
        key_info = (eapol_raw[5] << 8) | eapol_raw[6]
        if key_info != 0x8A:
            return None

        # Get the key data length
        key_data_length = (eapol_raw[117] << 8) | eapol_raw[118]

        # Key data must be at least 22 bytes (RSN IE + PMKID KDE)
        if key_data_length < 22:
            return None

        # Check for RSN IE tag (0x30) and PMKID KDE type (0x4)
        if eapol_raw[119] != 0x30 or eapol_raw[121] != 0x14:
            return None

        # Extract PMKID (16 bytes) starting at offset 125
        pmkid = eapol_raw[125:141].hex()

        # Get BSSID and Client MAC
        bssid = packet[wifi.Dot11].addr2
        client = packet[wifi.Dot11].addr1

        return f"{pmkid}*{bssid}*{client}"
    else:
        return None


def extract_handshake(packet):
    # Check if packet contains 802.11 (Wi-Fi) layer and EAPOL
    if packet.haslayer(wifi.Dot11) and packet.haslayer(eap.EAPOL):
        eapol_raw = bytes(packet[eap.EAPOL])

        # EAPOL frame must be at least 121 bytes
        if len(eapol_raw) < 121:
            return None

        # Check if it's EAPOL-Key frame (type = 3)
        if eapol_raw[1] != 3:
            return None

        # Get key information field
        key_info = (eapol_raw[5] << 8) | eapol_raw[6]

        # Check for Message 2 of the 4-way handshake
        # 0x010a = Message 2: 00010000 (pairwise=1, install=0, ack=0, mic=1, secure=0, error=0, request=1, encrypted=0)
        if key_info != 0x010A:
            return None

        # Extract the MIC from EAPOL frame
        mic = eapol_raw[89:105].hex()

        # Get BSSID (AP MAC) and Client MAC
        if packet[wifi.Dot11].FCfield & 0x2:  # ToDS bit set
            bssid = packet[wifi.Dot11].addr1  # AP is receiver
            client = packet[wifi.Dot11].addr2  # Client is sender
        else:
            bssid = packet[wifi.Dot11].addr2  # AP is sender
            client = packet[wifi.Dot11].addr1  # Client is receiver

        # Get ESSID from Dot11Elt layer if present
        essid = ""
        dot11_elt = packet.getlayer(wifi.Dot11Elt)
        while dot11_elt and essid == "":
            if dot11_elt.ID == 0:  # ESSID ID
                essid = dot11_elt.info.decode("utf-8", errors="ignore")
            dot11_elt = dot11_elt.payload if dot11_elt.payload else None

        if essid:
            # Format for hashcat: ESSID:MAC1:MAC2:MIC
            return f"{essid}*{bssid}*{client}*{mic}"

    return None


def process_captures(base_dir):
    pcap_dir = os.path.join(base_dir, PCAP_DIR)
    for file in os.scandir(pcap_dir):
        print(f"Processing {file.path} for handshakes and PMKIDs\n")
        packets = scapy.utils.rdpcap(file.path)
        hashcat_file = os.path.join(
            base_dir, HASHCAT_DIR, os.path.basename(file.path) + ".22000"
        )

        with open(hashcat_file, "w") as f:
            for p in packets:
                # Check for PMKID first
                pmkid = extract_pmkid(p)
                if pmkid is not None:
                    print(f"Found PMKID {pmkid} in {file.path}")
                    f.write("WPA*02*" + pmkid + "\n")
                    continue  # Skip handshake check if PMKID was found

                # Only check for handshake if no PMKID was found
                handshake = extract_handshake(p)
                if handshake is not None:
                    print(f"Found handshake {handshake} in {file.path}")
                    f.write("WPA*01*" + handshake + "\n")


if __name__ == "__main__":
    parser = build_args()
    args = parser.parse_args()

    sick_logo()

    if args.local_only:
        print("Local-only mode: preserving existing files and directories")
        setup_directories(args.handshake_dir, clean=False)
    else:
        if not args.host:
            parser.error("host argument is required when not using --local-only")
        setup_directories(args.handshake_dir, clean=True)
        transfer_handshakes(args.user, args.password, args.host, args.handshake_dir)

    process_captures(args.handshake_dir)
