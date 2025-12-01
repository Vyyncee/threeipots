from glob import glob
import pyshark
from csv import DictWriter

class ConvertSplit:

    HTTP = "HTTP"
    SMTP = "SMTP"
    SSH_TELNET = "SSH_TELNET"
    IPP_RAW_LPD = "IPP_RAW_LPD"

    # Paths and ports to retrieve .pcap files and split them
    PATH_ATTACK_PCAP = "/home/debian/tpotce/data/tcpdump/"
    PATH_CLEANED_PCAP = "/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data/threeipots/data/splited_normal_pcap/"
    PORTS_CLEANED = {SSH_TELNET: [22, 23], SMTP: [25, 587], HTTP: [80], IPP_RAW_LPD: [9100]}

    # Paths for attack data
    PATH_ATTACK_SPLIT = "/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data/threeipots/data/attack/"
    
    PATH_ATTACK_HTTP = PATH_ATTACK_SPLIT + "attacks_" + HTTP + ".csv"
    PATH_ATTACK_SMTP = PATH_ATTACK_SPLIT + "attacks_" + SMTP + ".csv"
    PATH_ATTACK_SSH_TELNET = PATH_ATTACK_SPLIT + "attacks_" + SSH_TELNET + ".csv"
    PATH_ATTACK_IPP_RAW_LPD = PATH_ATTACK_SPLIT + "attacks_" + IPP_RAW_LPD + ".csv"

    PATHS_ATTACK_SPLIT = {SSH_TELNET: PATH_ATTACK_SSH_TELNET, SMTP: PATH_ATTACK_SMTP, HTTP: PATH_ATTACK_HTTP, IPP_RAW_LPD: PATH_ATTACK_IPP_RAW_LPD}

    # Paths for normal data
    PATH_NORMAL_SPLIT = "/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data/threeipots/data/benin/"

    PATH_NORMAL_HTTP = PATH_NORMAL_SPLIT + "normal_" + HTTP + ".csv"
    PATH_NORMAL_SMTP = PATH_NORMAL_SPLIT + "normal_" + SMTP + ".csv"
    PATH_NORMAL_SSH_TELNET = PATH_NORMAL_SPLIT + "normal_" + SSH_TELNET + ".csv"
    PATH_NORMAL_IPP_RAW_LPD = PATH_NORMAL_SPLIT + "normal_" + IPP_RAW_LPD + ".csv"

    PATHS_NORMAL_SPLIT = {SSH_TELNET: PATH_NORMAL_SSH_TELNET, SMTP: PATH_NORMAL_SMTP, HTTP: PATH_NORMAL_HTTP, IPP_RAW_LPD: PATH_NORMAL_IPP_RAW_LPD}

    def __init__(self):

        # Define paths for retrieve all attack .pcap files
        self.attack_files_path = glob(self.PATH_ATTACK_PCAP + "*.pcap")

        self.normal_files_path = glob(self.PATH_CLEANED_PCAP + "*.pcap")

        # Define ports to split
        self.ports_to_split = self.PORTS_CLEANED

        self.ports_to_split_normal = self.PORTS_CLEANED

    def split(self):
        attacks_ssh_telnet = []
        attacks_smtp = []
        attacks_http = []
        attacks_ipp_raw_lpd = []

        # Sets pour collecter les colonnes uniques
        self.colonnes_ssh_telnet = set()
        self.colonnes_smtp = set()
        self.colonnes_http = set()
        self.colonnes_ipp_raw_lpd = set()

        for pcap in self.attack_files_path:
            capture = pyshark.FileCapture(pcap)
            try :
                for paquet in capture:
                    try: 
                        # Extraire les colonnes du paquet
                        colonnes = set()
                        for layer in paquet.layers:
                            for field in layer.field_names:
                                colonnes.add(layer.layer_name + "." + field)
                        # Extraire le port du paquet
                        port = paquet.udp.dstport if hasattr(paquet, 'udp') else paquet.tcp.dstport
                        if port is None:
                            continue
                        if int(port) in self.ports_to_split[self.SSH_TELNET]:
                            attacks_ssh_telnet.append(paquet)
                            self.colonnes_ssh_telnet.update(colonnes)
                        elif int(port) in self.ports_to_split[self.SMTP]:
                            attacks_smtp.append(paquet)
                            self.colonnes_smtp.update(colonnes)
                        elif int(port) in self.ports_to_split[self.HTTP]:
                            attacks_http.append(paquet)
                            self.colonnes_http.update(colonnes)
                        elif int(port) in self.ports_to_split[self.IPP_RAW_LPD]:
                            attacks_ipp_raw_lpd.append(paquet)
                            self.colonnes_ipp_raw_lpd.update(colonnes)
                    except Exception as e:
                        # Ignorer les paquets corrompues
                        continue
            except Exception as e:
                # Ignorer les fichiers pcap corrompues
                capture.close()
                continue
            capture.close()

        return (attacks_ssh_telnet, sorted(self.colonnes_ssh_telnet)), (attacks_smtp, sorted(self.colonnes_smtp)), \
                (attacks_http, sorted(self.colonnes_http)), (attacks_ipp_raw_lpd, sorted(self.colonnes_ipp_raw_lpd))


    def convert(self, write_paths):

        to_convert = self.split()

        for (paquets, colonnes), path in zip(to_convert, write_paths.values()):
            
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = DictWriter(f, fieldnames=colonnes)
                writer.writeheader()

                for paquet in paquets:
                    row = {}
                    for col in colonnes:
                        # Séparer layer.field
                        parts = col.split('.', 1)
                        layer_name = parts[0]
                        field_name = parts[1] if len(parts) > 1 else col
                        
                        # Récupérer la valeur
                        if hasattr(paquet, layer_name):
                            layer = getattr(paquet, layer_name)
                            row[col] = getattr(layer, field_name, '')
                        else:
                            row[col] = ''
                    writer.writerow(row)

    def convert_normal(self):

        for path, write_path in zip(sorted(self.normal_files_path), sorted(self.PATHS_NORMAL_SPLIT.values())):

            if self.HTTP in write_path:
                columns = sorted(self.colonnes_http)
            elif self.SMTP in write_path:
                columns = sorted(self.colonnes_smtp)
            elif self.SSH_TELNET in write_path:
                columns = sorted(self.colonnes_ssh_telnet)
            elif self.IPP_RAW_LPD in write_path:
                columns = sorted(self.colonnes_ipp_raw_lpd)         

            capture = pyshark.FileCapture(path)

            with open(write_path, 'w', newline='', encoding='utf-8') as f:
                writer = DictWriter(f, fieldnames=columns)
                writer.writeheader()

                for paquet in capture:
                    try:
                        row = {}
                        for col in columns:
                            # Séparer layer.field
                            parts = col.split('.', 1)
                            layer_name = parts[0]
                            field_name = parts[1] if len(parts) > 1 else col
                            
                            # Récupérer la valeur
                            if hasattr(paquet, layer_name):
                                layer = getattr(paquet, layer_name)
                                row[col] = getattr(layer, field_name, '')
                            else:
                                row[col] = ''
                        writer.writerow(row)
                    except Exception as e:
                        # Ignorer les paquets corrompues
                        continue
            capture.close()


if __name__ == "__main__":        
    convertAndSplit = ConvertSplit()
    convertAndSplit.convert(ConvertSplit.PATHS_ATTACK_SPLIT)
    convertAndSplit.convert_normal()
