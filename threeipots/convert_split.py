from glob import glob
import pyshark
from csv import DictWriter
import pandas as pd
from threeipots.utils.protocol import Protocol
from threeipots.utils.packet_utils import PacketUtils
from multiprocessing import Process, Manager
import time

class ConvertSplit:

    ATTACK_PART_PATH = "attacks_"
    CSV = ".csv"
    NORMAL_PART_PATH = "normal_"

    # Paths and ports to retrieve .pcap files and split them
    PATH_ATTACK_PCAP = "/home/debian/tpotce/data/tcpdump/"
    PATH_CLEANED_PCAP = "/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data/threeipots/data/splited_normal_pcap/"

    # Paths for attack data
    PATH_ATTACK_SPLIT = "/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data/threeipots/data/attack/"
    
    # Paths for normal data
    PATH_NORMAL_SPLIT = "/home/debian/1-Projet_honeypot_dev_by_us_the_goup/1-Centralisation_data/threeipots/data/benin/"

    def __init__(self):

        # Define paths for retrieve all attack .pcap files
        self.attack_files_path = sorted(glob(self.PATH_ATTACK_PCAP + "*.pcap"))

        # Define paths for retrieve all normal .pcap files
        self.normal_files_path = glob(self.PATH_CLEANED_PCAP + "*.pcap")

    @staticmethod
    def pcap_worker(pcaps, ports, attacks_split, i):
        attacks = []
        for pcap in pcaps:
            capture = pyshark.FileCapture(pcap)
            try :
                for paquet in capture:
                    try: 
                        # Extraire les données du paquet
                        row = PacketUtils.toDict(paquet)

                        # Extraire le port du paquet
                        dst_port = paquet.udp.dstport if hasattr(paquet, 'udp') else paquet.tcp.dstport
                        src_port = paquet.udp.srcport if hasattr(paquet, 'udp') else paquet.tcp.srcport

                        if dst_port is None and src_port is None:
                            continue
                        if int(dst_port) in ports or int(src_port) in ports:
                            attacks.append(row)

                    except Exception as e:
                        # Ignorer les paquets corrompues
                        continue
            except Exception as e:
                # Ignorer les fichiers pcap corrompues
                capture.close()
            capture.close()
        
        attacks_split[i] = attacks

    def retrieve_attacks_by_port(self, ports, num_processes=8):
        attacks = []

        # Diviser la liste en sous-listes selon le nombre de processus
        taille = len(self.attack_files_path) // num_processes
        sous_listes = [self.attack_files_path[i*taille : (i+1)*taille] for i in range(num_processes-1)]
        sous_listes.append(self.attack_files_path[(num_processes-1)*taille:])

        with Manager() as manager:
            attacks_split = manager.list([None]*num_processes)

            processes = []
            for i, sublist in enumerate(sous_listes):
                p = Process(target=ConvertSplit.pcap_worker, args=(sublist, ports, attacks_split, i))
                processes.append(p)
                p.start()

            for p in processes:
                p.join()

            # Combiner tous les résultats
            attacks = [elem for attack in attacks_split if attack for elem in attack]

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
    start_time = time.time()  # démarre le chronomètre
    attacks = convertAndSplit.retrieve_attacks_by_port(Protocol.SSH_TELNET.value)

    end_time = time.time()    # arrête le chronomètre
    elapsed_time = end_time - start_time

    print(f"La fonction a mis {elapsed_time:.3f} secondes.")
    
    print('Attaques ' + Protocol.SSH_TELNET.name + ' trouvées.')
    columns = convertAndSplit.write_attacks(attacks, Protocol.SSH_TELNET.name)
    print('Attaques ' + Protocol.SSH_TELNET.name + ' écrites.')
    convertAndSplit.write_normal(columns, Protocol.SSH_TELNET.name)
    print('Normales ' + Protocol.SSH_TELNET.name + ' écrites.')

    # HTTP
    # attacks = convertAndSplit.retrieve_attacks_by_port(Protocol.HTTP.value)
    # print('Attaques ' + Protocol.HTTP.name + ' trouvées.')
    # columns = convertAndSplit.write_attacks(attacks, Protocol.HTTP.name)
    # print('Attaques ' + Protocol.HTTP.name + ' écrites.')
    # convertAndSplit.write_normal(columns, Protocol.HTTP.name)
    # print('Normales ' + Protocol.HTTP.name + ' écrites.')

    # # SMTP
    # attacks = convertAndSplit.retrieve_attacks_by_port(Protocol.SMTP.value)
    # print('Attaques ' + Protocol.SMTP.name + ' trouvées.')
    # columns = convertAndSplit.write_attacks(attacks, Protocol.SMTP.name)
    # print('Attaques ' + Protocol.SMTP.name + ' écrites.')
    # convertAndSplit.write_normal(columns, Protocol.SMTP.name)
    # print('Normales ' + Protocol.SMTP.name + ' écrites.')

    # RAW

    # start_time = time.time()  # démarre le chronomètre

    # attacks = convertAndSplit.retrieve_attacks_by_port(Protocol.RAW.value)

    # end_time = time.time()    # arrête le chronomètre
    # elapsed_time = end_time - start_time

    # print(f"La fonction a mis {elapsed_time:.3f} secondes.")

    # print('Attaques ' + Protocol.RAW.name + ' trouvées.')
    # columns = convertAndSplit.write_attacks(attacks, Protocol.RAW.name)
    # print('Attaques ' + Protocol.RAW.name + ' écrites.')
    # convertAndSplit.write_normal(columns, Protocol.RAW.name)
    # print('Normales ' + Protocol.RAW.name + ' écrites.')

