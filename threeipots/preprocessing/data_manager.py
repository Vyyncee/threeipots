from glob import glob
from threeipots.convert_split import ConvertSplit
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

class DataManager:

    INFECTED = "Infected"
    CLEAN = "Clean"

    mapping = {CLEAN: 0, INFECTED: 1}
    inverse_mapping = {0: CLEAN, 1: INFECTED}

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

    def remove_columns_by_null_threshold(self, key, threshold=0.15):
        df = self.merged[key]
        initial_columns = df.shape[1]

        non_null_threshold = threshold * len(df)
        # Supprimer les colonnes avec moins de threshold% de valeurs non nulles
        df = df.dropna(axis=1, thresh=non_null_threshold)

        final_columns = df.shape[1]
        print(f"Colonnes supprimées dans {key} en raison du seuil de valeurs non nulles: {initial_columns - final_columns}")

        self.merged[key] = df

    def show_null_values_columns(self):
        for key, df in self.merged.items():
            plt.figure(figsize=(12, 6))
            sns.heatmap(df.isnull(), cbar=False, yticklabels=False, cmap='viridis')
            plt.title(f"Valeurs manquantes dans le dataset: {key}")
            plt.show()
    
    def fill_missing_values(self, key):
        df = self.merged[key]

        for col in df.select_dtypes(include=['float64', 'int64']).columns:
            if df[col].isnull().any():
                # Remplacer les valeurs nulles par la valeur moyenne de la colonne
                mean = df[col].mean()
                df[col].fillna(mean, inplace=True)
        
        # Pour les colonnes catégorielles, remplacer les NaN par la valeur la plus fréquente
        for col in df.select_dtypes(include=['object']).columns:
            if df[col].isnull().any():
                mode = df[col].mode()[0]
                df[col].fillna(mode, inplace=True)

        self.merged[key] = df

    def remove_columns(self, key, column_names):
        for column_name in column_names:
            self.remove_column(key, column_name)

    def remove_column(self, key, column_name):
        if column_name in self.merged[key].columns:
            self.merged[key].drop(columns=[column_name], inplace=True)

    def have_unique_value_columns(self, key):
        unique_columns = []
        for col in self.merged[key].columns:
            if self.merged[key][col].nunique() == 1:
                unique_columns.append(col)
        return unique_columns
    
    def drop_duplicates_columns(self, key):
        self.merged[key] = self.merged[key].loc[:, ~self.merged[key].T.duplicated()]

    def standardisation(self, key):
        numeric_cols = self.merged[key].select_dtypes(include=['number']).columns
        scaler = StandardScaler()
        self.merged[key][numeric_cols] = scaler.fit_transform(self.merged[key][numeric_cols])
    
    def encode(self, key):
        categorical_cols = self.merged[key].select_dtypes(exclude=['number']).columns.drop('label')

        for col in categorical_cols:
            le = LabelEncoder()
            self.merged[key][col] = le.fit_transform(self.merged[key][col])
        
        self.merged[key]['label'] = self.merged[key]['label'].map(self.mapping)

    def decode_label(self, prediction):
        return [self.inverse_mapping[i] for i in prediction]

    def balance(self, key, random_state=42):
        # Taille de la classe minoritaire
        min_count = self.merged[key]['label'] .value_counts().min()
        
        # Sous-échantillonnage de chaque classe à la taille de la classe minoritaire
        balanced_df = pd.concat([
            self.merged[key][self.merged[key]['label'] == cls].sample(n=min_count, random_state=random_state)
            for cls in self.merged[key]['label'].unique()
        ])
        
        # Mélanger les lignes
        return balanced_df.sample(frac=1, random_state=random_state).reset_index(drop=True)


        

        
