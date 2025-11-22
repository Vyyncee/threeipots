import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
    roc_curve, roc_auc_score, precision_recall_curve
)

class RateModels:
    def __init__(self, models=None, datasets=None):
        self.models = models if models else {}
        self.datasets = datasets if datasets else []

    def add_model(self, name, model):
        self.models[name] = model

    def add_dataset(self, X, y):
        self.datasets.append((X, y))

    def evaluate_model(self, model, X, y, visualize=False):

        y_pred = model.predict(X)
        y_prob = model.predict_proba(X)[:, 1]

        metrics = {
            "accuracy": accuracy_score(y, y_pred),
            "precision": precision_score(y, y_pred, zero_division=0),
            "recall": recall_score(y, y_pred, zero_division=0),
            "f1_score": f1_score(y, y_pred, zero_division=0),
            "confusion_matrix": confusion_matrix(y, y_pred),
            "classification_report": classification_report(y, y_pred, zero_division=0),
            "roc_auc": roc_auc_score(y, y_prob),
            "y_prob": y_prob,
        }

        if visualize:
            self._visualize(model_name=model.__class__.__name__, y=y, metrics=metrics)

        return metrics

    def evaluate_models(self, visualize=False):
        results = {}

        for model_name, model in self.models.items():
            print(f"\n===== {model_name} =====")
            results[model_name] = []

            for i, (X, y) in enumerate(self.datasets):
                print(f"\n--- Dataset {i} ---")

                metrics = self.evaluate_model(model, X, y, visualize=visualize)
                results[model_name].append(metrics)

                print(f"Accuracy : {metrics['accuracy']:.4f}")
                print(metrics['classification_report'])

        return results

    def _visualize(self, model_name, y, metrics):
        cm = metrics["confusion_matrix"]
        y_prob = metrics["y_prob"]

        self._plot_confusion_matrix(cm, model_name)
        self._plot_roc_curve(y, y_prob, model_name)
        self._plot_precision_recall(y, y_prob, model_name)

    def _plot_confusion_matrix(self, cm, model_name):
        plt.figure(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
        plt.title(f"Matrice de confusion - {model_name}")
        plt.xlabel("Prédit")
        plt.ylabel("Réel")
        plt.show()

    def _plot_roc_curve(self, y, y_prob, model_name):
        fpr, tpr, _ = roc_curve(y, y_prob)
        plt.figure(figsize=(6, 5))
        plt.plot(fpr, tpr, linewidth=2)
        plt.plot([0, 1], [0, 1], "--")
        plt.title(f"ROC Curve - {model_name}")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.grid(True)
        plt.show()

    def _plot_precision_recall(self, y, y_prob, model_name):
        precision, recall, _ = precision_recall_curve(y, y_prob)
        plt.figure(figsize=(6, 5))
        plt.plot(recall, precision, linewidth=2)
        plt.title(f"Precision–Recall Curve - {model_name}")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.grid(True)
        plt.show()
