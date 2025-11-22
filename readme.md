# Projet 3IPOTS

## TODO

- Supprimer les colonnes doublées, supprimer les colonne qui ont toute les meme valeurs pour chaque ligne
- Pour le rééquilibrage, a la place de supprimer des ligne, pioché le nombre de ligne qu'il faut -> Pour éviter la suppression de données
- Supprimer les lignes ou c'est nous qui envoyons la requête ???
- Utilisation des données de TPOT (Savoir si c'est un brut force par exemple, la labellisation plus complète etc...) ???
- Ne pas normaliser toutes les colonnes (exemple : IP, etc...)

Test

Etapes de suppresion des colonnes inutiles :
- Supprimer les colonnes avec plus de 85% de valeur null
- Supprimer les colonnes pour lesquels la valeurs de chaque ligne est la même
- Supprimer les colonnes doublons
- Separer les date, les adresse ip pour avoir des valeurs compréensible par nos model

Est ce que si on a plus de genre 80% des valeurs d'une colonne qui sont identique, ont supprime la colonne ???

- Ajout de GridSearchCV pour l'optimisation des hyperparamètres des modèles pour ensuite faire une comparaison avec les modèles en générale et ensuite les intégrer oui ou non a des modèles d'ensemble (pas besoin de le faire si le modèle est déjà optimisé).