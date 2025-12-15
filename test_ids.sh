#!/bin/bash

# ============================
# CONFIGURATION GÉNÉRALE
# ============================

TARGET_URL="http://147.135.213.152"
CONTAINER_NAME="site_web_test-web-1"
COOKIE_JAR="session_cookie.txt"

PROJECT_PATH="/home/debian/1-Projet_honeypot_dev_by_us_the_goup/site_web_test"

MIN_DELAY=1
MAX_DELAY=4

USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

COMMON_HEADERS=(
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
  -H "Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
  -H "Accept-Encoding: gzip, deflate"
  -H "Connection: keep-alive"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Cache-Control: max-age=0"
)

cd "$PROJECT_PATH" || exit 1

# ============================
# FONCTIONS
# ============================

human_delay() {
    delay=$(shuf -i $MIN_DELAY-$MAX_DELAY -n 1)
    echo "⏳ Pause humaine : ${delay}s"
    sleep "$delay"
}

send_request() {
    METHOD=$1
    URI=$2
    PARAMS=$3
    REFERER=$4

    echo -e "\n=== REQUÊTE HTTP ==="
    echo "→ METHOD  : $METHOD"
    echo "→ URL     : $TARGET_URL$URI"
    echo "→ PARAMS  : $PARAMS"
    echo "→ REFERER : $TARGET_URL$REFERER"

    human_delay

    if [ "$METHOD" = "GET" ]; then
        curl -s \
            -b "$COOKIE_JAR" \
            -A "$USER_AGENT" \
            "${COMMON_HEADERS[@]}" \
            -H "Referer: $TARGET_URL$REFERER" \
            "$TARGET_URL$URI?$PARAMS" \
            > /dev/null 2>&1
    else
        curl -s \
            -b "$COOKIE_JAR" \
            -A "$USER_AGENT" \
            "${COMMON_HEADERS[@]}" \
            -H "Referer: $TARGET_URL$REFERER" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -X POST \
            -d "$PARAMS" \
            "$TARGET_URL$URI" \
            > /dev/null 2>&1
    fi

    echo "✔️ Trame envoyée (session active)"
    echo "-----------------------------------"
}

# ============================
# VÉRIFICATION DU CONTENEUR
# ============================

container_status=$(docker ps -q -f "name=$CONTAINER_NAME")

if [ -z "$container_status" ]; then
    echo "⚠️  Conteneur $CONTAINER_NAME arrêté"
    echo "🚀 Démarrage..."
    docker compose up -d
    sleep 3

    container_status=$(docker ps -q -f "name=$CONTAINER_NAME")
    if [ -z "$container_status" ]; then
        echo "❌ Échec du démarrage du conteneur"
        exit 1
    fi
else
    echo "✅ Conteneur déjà actif"
fi

# ============================
# INITIALISATION SESSION
# ============================

echo "🔐 Initialisation session PHP"
curl -s -c "$COOKIE_JAR" \
     -A "$USER_AGENT" \
     "${COMMON_HEADERS[@]}" \
     "$TARGET_URL/login.php" > /dev/null 2>&1

if [ ! -s "$COOKIE_JAR" ]; then
    echo "❌ Cookie de session non récupéré"
    exit 1
fi

echo "✅ Cookie de session créé"
echo "-----------------------------------"

# ============================
# SCÉNARIO DE NAVIGATION
# ============================

echo "==== DÉBUT DES TESTS IDS ===="

# Navigation bénigne
send_request "GET"  "/index.php" "" "/"
send_request "GET"  "/login.php" "" "/index.php"
send_request "POST" "/validation_login" "login=test&password=test" "/login.php"
send_request "GET"  "/enseignant/quizz" "" "/index.php"

# Attaque : Path Traversal
send_request "GET" "/../../../etc/passwd" "" "/enseignant/quizz"

# Navigation normale
send_request "POST" "/enseignant/creationQuizz" "" "/enseignant/quizz"
send_request "POST" "/enseignant/NewQuizz" "name=test2&desc=a" "/enseignant/creationQuizz"

# Attaque : XSS stockée
send_request "POST" "/enseignant/NewQuizz" "name=<script>alert(1)</script>&desc=a" "/enseignant/creationQuizz"

# Déconnexion
send_request "GET" "/compte/deconnexion" "" "/enseignant/quizz"

# Nettoyage cookie
rm -f "$COOKIE_JAR"

# Attaque : SQLi post logout
send_request "POST" "/validation_login" "login=' OR 1=1 -- &password=xx" "/login.php"

echo -e "\n==== TESTS TERMINÉS ====\n"

# ============================
# ARRÊT DU CONTENEUR
# ============================

echo "🛑 Arrêt du conteneur"
docker compose down > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Conteneur arrêté proprement"
else
    echo "❌ Problème à l'arrêt du conteneur"
fi

echo "🎉 FIN DU SCRIPT"
