from glob import glob
from threeipots.convert_split import ConvertSplit
import pandas as pd

class DataManager:

    INFECTED = "Infected"
    CLEAN = "Clean"

    def __init__(self):

        self.paths_benin = glob(ConvertSplit.PATH_NORMAL_SPLIT + "*.csv")
        self.paths_attack = glob(ConvertSplit.PATH_ATTACK_SPLIT + "*.csv")

        self.benin = self.get_datas_benin()
        self.attacks = self.get_datas_attack()

        self.merged = {}

    def get_datas_benin(self):
        self.benin = {}

        for path in self.paths_benin:
            if ConvertSplit.HTTP in path:
                self.benin[ConvertSplit.HTTP] = pd.read_csv(path, low_memory=False)
            elif ConvertSplit.SSH_TELNET in path:
                self.benin[ConvertSplit.SSH_TELNET] = pd.read_csv(path, low_memory=False)
            elif ConvertSplit.SMTP in path:
                self.benin[ConvertSplit.SMTP] = pd.read_csv(path, low_memory=False)
            elif ConvertSplit.IPP_RAW_LPD in path:
                self.benin[ConvertSplit.IPP_RAW_LPD] = pd.read_csv(path, low_memory=False)

        return self.benin


    def get_datas_attack(self):
        self.attacks = {}

        for path in self.paths_attack:
            if ConvertSplit.HTTP in path:
                self.attacks[ConvertSplit.HTTP] = pd.read_csv(path, low_memory=False)
            elif ConvertSplit.SSH_TELNET in path:
                self.attacks[ConvertSplit.SSH_TELNET] = pd.read_csv(path, low_memory=False)
            elif ConvertSplit.SMTP in path:
                self.attacks[ConvertSplit.SMTP] = pd.read_csv(path, low_memory=False)
            elif ConvertSplit.IPP_RAW_LPD in path:
                self.attacks[ConvertSplit.IPP_RAW_LPD] = pd.read_csv(path, low_memory=False)

        return self.attacks

    def add_label_column(self, key, label):
        if label == self.INFECTED:
            self.attacks[key]['label'] = label
        elif label == self.CLEAN:
            self.benin[key]['label'] = label

    def merge_dataframes(self, key):

        df_benin = self.benin[key]
        print(f"Benin (Ligne, Colonne) {key}: {df_benin.shape}")

        df_attack = self.attacks[key]
        print(f"Attaques (Ligne, Colonne) {key}: {df_attack.shape}")

        merged_df = pd.concat([df_benin, df_attack], ignore_index=True)
        print(f"Dataframe fusionné (Ligne, Colonne) {key}: {merged_df.shape}")

        self.merged[key] = merged_df
    
    def remove_duplicates(self, key):
        duplicated_count = self.merged[key].duplicated().sum()
        print(f"Nombre de lignes dupliquées dans {key}: {duplicated_count}")

        if(duplicated_count > 0):
            self.merged[key].drop_duplicates(inplace=True)

        return self.merged[key]

    
        
        