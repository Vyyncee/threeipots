from glob import glob
import pyshark
from csv import DictWriter
import pandas as pd

class ConvertSplit:

    ATTACK_PART_PATH = "attacks_"
    CSV = ".csv"
    NORMAL_PART_PATH = "normal_"

    # Protocols name
    HTTP = "HTTP"
    SMTP = "SMTP"
    SSH_TELNET = "SSH_TELNET"
    IPP_RAW_LPD = "IPP_RAW_LPD"

    # Paths and ports to retrieve .pcap files and split them
    PATH_ATTACK_PCAP = "/home/debian/tpotce/data/tcpdump/"
    PATH_CLEANED_PCAP = "/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data/threeipots/data/splited_normal_pcap/"
    
    # Ports by protocol
    PORTS = {SSH_TELNET: [22, 23], SMTP: [25, 587], HTTP: [80], IPP_RAW_LPD: [9100]}

    # Paths for attack data
    PATH_ATTACK_SPLIT = "/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data/threeipots/data/attack/"
    
    # Paths for normal data
    PATH_NORMAL_SPLIT = "/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data/threeipots/data/benin/"

    def __init__(self):

        # Define paths for retrieve all attack .pcap files
        self.attack_files_path = sorted(glob(self.PATH_ATTACK_PCAP + "*.pcap"))

        # Define paths for retrieve all normal .pcap files
        self.normal_files_path = glob(self.PATH_CLEANED_PCAP + "*.pcap")

    def search_attacks_by_port(self, ports):
        attacks = []

        for pcap in self.attack_files_path:

            if len(attacks) > 35000:
                break

            capture = pyshark.FileCapture(pcap)
            try :
                for paquet in capture:
                    if len(attacks) > 35000:
                        break

                    try: 
                        # Extraire les données du paquet
                        row = {}
                        for layer in paquet.layers:
                            for field in layer.field_names:
                                name = layer.layer_name + "." + field

                                # Récupérer la valeur
                                if hasattr(paquet, layer.layer_name):
                                    layer = getattr(paquet, layer.layer_name)
                                    row[name] = getattr(layer, field, '')
                                else:
                                    row[name] = ''

                        # Extraire le port du paquet
                        port = paquet.udp.dstport if hasattr(paquet, 'udp') else paquet.tcp.dstport

                        if port is None:
                            continue
                        if int(port) in ports:
                            attacks.append(row)

                    except Exception as e:
                        # Ignorer les paquets corrompues
                        continue
            except Exception as e:
                # Ignorer les fichiers pcap corrompues
                capture.close()
                continue

            capture.close()

        return attacks
    
    def write_attacks(self, attacks, protocol):
        path = self.PATH_ATTACK_SPLIT + self.ATTACK_PART_PATH + protocol + self.CSV
        df = pd.DataFrame(attacks)
        df.to_csv(path, index=False)

        return list(df.columns)

    def write_normal(self, columns, protocol):

        # Path to write the csv
        path = self.PATH_NORMAL_SPLIT  + self.NORMAL_PART_PATH + protocol + self.CSV

        # Path to read the pcap
        right_file = next((f for f in self.normal_files_path if protocol in f), None)
        if right_file is None :
            raise Exception("Fichier introuvable")

        capture = pyshark.FileCapture(right_file)
        with open(path, 'w', newline='', encoding='utf-8') as f:
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
                            row[col] = getattr(layer, field_name, None)
                        else:
                            row[col] = None

                    writer.writerow(row)
                except Exception as e:
                    # Ignorer les paquets corrompues
                    continue

        capture.close()


if __name__ == "__main__":        
    convertAndSplit = ConvertSplit()

    # SSH_TELNET
    attacks = convertAndSplit.search_attacks_by_port(ConvertSplit.PORTS[ConvertSplit.SSH_TELNET])
    print('Attaques ' + ConvertSplit.SSH_TELNET + ' trouvées.')
    columns = convertAndSplit.write_attacks(attacks, ConvertSplit.SSH_TELNET)
    print('Attaques ' + ConvertSplit.SSH_TELNET + ' écrites.')
    convertAndSplit.write_normal(columns, ConvertSplit.SSH_TELNET)
    print('Normales ' + ConvertSplit.SSH_TELNET + ' écrites.')

    # HTTP
    attacks = convertAndSplit.search_attacks_by_port(ConvertSplit.PORTS[ConvertSplit.HTTP])
    print('Attaques ' + ConvertSplit.HTTP + ' trouvées.')
    columns = convertAndSplit.write_attacks(attacks, ConvertSplit.HTTP)
    print('Attaques ' + ConvertSplit.HTTP + ' écrites.')
    convertAndSplit.write_normal(columns, ConvertSplit.HTTP)
    print('Normales ' + ConvertSplit.HTTP + ' écrites.')

    # SMTP
    attacks = convertAndSplit.search_attacks_by_port(ConvertSplit.PORTS[ConvertSplit.SMTP])
    print('Attaques ' + ConvertSplit.SMTP + ' trouvées.')
    columns = convertAndSplit.write_attacks(attacks, ConvertSplit.SMTP)
    print('Attaques ' + ConvertSplit.SMTP + ' écrites.')
    convertAndSplit.write_normal(columns, ConvertSplit.SMTP)
    print('Normales ' + ConvertSplit.SMTP + ' écrites.')

    # IPP_LPD_RAW
    attacks = convertAndSplit.search_attacks_by_port(ConvertSplit.PORTS[ConvertSplit.IPP_RAW_LPD])
    print('Attaques ' + ConvertSplit.IPP_RAW_LPD + ' trouvées.')
    columns = convertAndSplit.write_attacks(attacks, ConvertSplit.IPP_RAW_LPD)
    print('Attaques ' + ConvertSplit.IPP_RAW_LPD + ' écrites.')
    convertAndSplit.write_normal(columns, ConvertSplit.IPP_RAW_LPD)
    print('Normales ' + ConvertSplit.IPP_RAW_LPD + ' écrites.')

