from glob import glob
from threeipots.convert_split import ConvertSplit
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import OrdinalEncoder
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from threeipots.utils.protocol import Protocol
from threeipots.utils.transformer.transform import transform_row
from sklearn.model_selection import GroupShuffleSplit

class DataManager:

    INFECTED = "Infected"
    CLEAN = "Clean"

    mapping = {CLEAN: 0, INFECTED: 1}
    inverse_mapping = {0: CLEAN, 1: INFECTED}

    ##############
    #### INIT ####
    ##############

    def __init__(self):

        self.paths_benin = glob(ConvertSplit.PATH_NORMAL_SPLIT + "*.csv")
        self.paths_attack = glob(ConvertSplit.PATH_ATTACK_SPLIT + "*.csv")

        self.benin = self.get_datas_benin()
        self.attacks = self.get_datas_attack()

        self.merged = {}

    def get_datas_benin(self):
        self.benin = {}

        for path in self.paths_benin:
            for proto in Protocol:
                if proto.name in path:
                    self.benin[proto] = pd.read_csv(path, low_memory=False)
                    break

        return self.benin


    def get_datas_attack(self):
        self.attacks = {}

        for path in self.paths_attack:
            for proto in Protocol:
                if proto.name in path:
                    self.attacks[proto] = pd.read_csv(path, low_memory=False)
                    break

        return self.attacks

    #######################
    #### PREPROCESSING ####
    #######################

    @staticmethod
    def transform_df(df, protocol):
        return pd.DataFrame(df.apply(lambda row: transform_row(row, protocol), axis=1).tolist())

    def transform(self):
        for key, df in self.benin.items():
            self.benin[key] = DataManager.transform_df(df, key)
        for key, df in self.attacks.items():
            self.attacks[key] = DataManager.transform_df(df, key)

    #######################

    def impute_median(self):
        for key, df in self.benin.items():
            numeric_cols = df.select_dtypes(include='number').columns
            self.benin[key][numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())

        for key, df in self.attacks.items():
            numeric_cols = df.select_dtypes(include='number').columns
            self.attacks[key][numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
    
    #######################

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

    @staticmethod
    def get_preprocessor(df):

        # Colonne numérique pour le Scaling
        numeric_cols = df.select_dtypes(include=['number']).columns.drop('label')

        # Colonne categorielle pour l'encodage
        categorical_cols = df.select_dtypes(exclude=['number']).columns.drop('flow_id')

        preprocessor = ColumnTransformer([
            ("num", StandardScaler(), numeric_cols),
            ("cat", OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1), categorical_cols)
        ])

        return preprocessor
    
    def encode_label(self, key):
        self.merged[key]['label'] = self.merged[key]['label'].map(self.mapping)

    @staticmethod
    def decode_label(prediction):
        return [DataManager.inverse_mapping[i] for i in prediction]

    def balance(self, key, random_state=42):
        # Taille de la classe minoritaire
        min_count = self.merged[key]['label'].value_counts().min()
        
        # Sous-échantillonnage de chaque classe à la taille de la classe minoritaire
        balanced_df = pd.concat([
            self.merged[key][self.merged[key]['label'] == cls].sample(n=min_count, random_state=random_state)
            for cls in self.merged[key]['label'].unique()
        ])
        
        return balanced_df

    @staticmethod
    def get_flow_id(row):
        pair1 = (row['src_ip'], row['src_port'])
        pair2 = (row['dst_ip'], row['dst_port'])
        return tuple(sorted([pair1, pair2]))
    
    def add_flow_id(self, key):
        self.merged[key]['flow_id'] = self.merged[key].apply(DataManager.get_flow_id, axis=1)

    @staticmethod
    def mix_split(df):
        """
        df : DataFrame avec au moins les colonnes ['flow_id', 'label']
        """

        # Regrouper par flow_id et prendre y du premier paquet de chaque flux
        flows_df = df.groupby('flow_id')['label'].first().reset_index()

        # Split train/test stratifié sur y
        train_flows, test_flows = train_test_split(
            flows_df, test_size=0.2, stratify=flows_df['label'], random_state=42
        )

        # Récupérer les paquets correspondants
        X_train = df[df['flow_id'].isin(train_flows['flow_id'])].drop(columns=['label', 'flow_id'])
        y_train = df[df['flow_id'].isin(train_flows['flow_id'])]['label']
        X_test = df[df['flow_id'].isin(test_flows['flow_id'])].drop(columns=['label', 'flow_id'])
        y_test = df[df['flow_id'].isin(test_flows['flow_id'])]['label']

        return X_train, X_test, y_train, y_test
