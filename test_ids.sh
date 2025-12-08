#!/bin/bash

TARGET_URL="http://147.135.213.152"
CONTAINER_NAME="site_web_test-web-1"
COOKIE_JAR="session_cookie.txt"
cd /home/debian/1-Projet_honeypot_dev_by_us_the_goup/site_web_test
# ============================
# Check si le conteneur tourne
# ============================

container_status=$(docker ps -q -f "name=$CONTAINER_NAME")

if [ -z "$container_status" ]; then
    echo "⚠️  Le conteneur $CONTAINER_NAME n'est pas démarré."
    echo "🚀  Démarrage du conteneur..."
    docker compose up -d

    sleep 3

    container_status=$(docker ps -q -f "name=$CONTAINER_NAME")
    if [ -z "$container_status" ]; then
        echo "❌ Impossible de démarrer le conteneur. Abandon."
        exit 1
    else
        echo "✅ Conteneur démarré."
    fi
else
    echo "✅ Le conteneur $CONTAINER_NAME est déjà UP."
fi


# ============================
# Connexion pour obtenir la session
# ============================

# Sert à naviguer dans le site, bénin
curl -s -c "$COOKIE_JAR" "$TARGET_URL/login.php" > /dev/null 2>&1

if [ ! -s "$COOKIE_JAR" ]; then
    echo "❌ Aucun cookie récupéré — Impossible d’établir une session."
    exit 1
fi

echo "✅ Cookie de session récupéré ($COOKIE_JAR)"
echo "-----------------------------------"


# ============================
# Fonction d'envoi de requêtes
# ============================

send_request() {
    METHOD=$1
    URI=$2
    PARAMS=$3
    USERAGENT=$4

    echo -e "\n=== $TYPE ==="
    echo "→ METHOD : $METHOD"
    echo "→ URL    : $TARGET_URL$URI"
    echo "→ PARAMS : $PARAMS"

    if [ "$METHOD" = "GET" ]; then
        curl -s -b "$COOKIE_JAR" -A "$USERAGENT" "$TARGET_URL$URI?$PARAMS" > /dev/null 2>&1
    else
        curl -s -b "$COOKIE_JAR" -X POST -A "$USERAGENT" -d "$PARAMS" "$TARGET_URL$URI" > /dev/null 2>&1
    fi

    echo -e "✔️ Requête envoyée avec session PHP.\n-----------------------------------"
}

echo "==== DÉBUT DES TESTS ===="
# Bénin
send_request "GET" "/index.php" "" "Mozilla/5.0"
# Bénin
send_request "GET" "/login.php" "" "Mozilla/5.0"
# Bénin
send_request "POST" "/validation_login" "login=test&password=test" "Mozilla/5.0"
# Bénin
send_request "GET" "/enseignant/quizz" "" "Mozilla/5.0"
# Malveillant
send_request "GET" "/../../../etc/passwd" "" "Mozilla/5.0"
# Bénin
send_request "POST" "/enseignant/creationQuizz" "" "Mozilla/5.0"
# Bénin
send_request "POST" "/enseignant/NewQuizz" "name=test2&desc=a" "Mozilla/5.0"
# Malveillant
send_request "POST" "/enseignant/NewQuizz" "name=<script>alert(1)</script>&desc=a" "Mozilla/5.0"
# Bénin
send_request "GET" "/compte/deconnexion" "" "Mozilla/5.0"
# Nettoyage cookie
rm -f "$COOKIE_JAR"
# Malveillant
send_request "POST" "/validation_login" "login=' OR 1=1 -- &password=xx" "Mozilla/5.0"

echo -e "\n==== TESTS TERMINÉS ====\n"


# ============================
# 🛑 Stop du conteneur
# ============================

echo "🛑 Arrêt du conteneur $CONTAINER_NAME ..."
docker compose down > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Conteneur arrêté proprement."
else
    echo "❌ Impossible d'arrêter le conteneur."
fi

echo "🎉 FIN DU SCRIPT"
