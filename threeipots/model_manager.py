import matplotlib.pyplot as plt
import os
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from joblib import dump

class ModelManager:

    PATH_SAVE = os.path.join(os.path.dirname(__file__), 'ids', 'models')
    SUFFIX_FOR_SAVE_VOTING = '.joblib'

    @staticmethod
    def save(to_save, name):
        os.makedirs(ModelManager.PATH_SAVE, exist_ok=True)
        path = os.path.join(ModelManager.PATH_SAVE, name)
        dump(to_save, path)

    @staticmethod
    def eval(y_pred, y):

        metrics = {
            "accuracy": accuracy_score(y, y_pred),
            "precision": precision_score(y, y_pred, zero_division=0),
            "recall": recall_score(y, y_pred, zero_division=0),
            "f1_score": f1_score(y, y_pred, zero_division=0),
            "confusion_matrix": confusion_matrix(y, y_pred),
            "classification_report": classification_report(y, y_pred, zero_division=0)
        }

        # Affichage simple
        print("=== Scores Globaux ===")
        print(f"Accuracy : {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall   : {metrics['recall']:.4f}")
        print(f"F1 Score : {metrics['f1_score']:.4f}\n")

        # Affichage matrice de confusion
        print("=== Confusion Matrix ===")
        print(metrics['confusion_matrix'], "\n")

        # Affichage classification report
        print("=== Classification Report ===")
        print(metrics['classification_report'])

        return metrics
