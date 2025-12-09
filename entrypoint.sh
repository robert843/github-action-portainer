#!/bin/sh
set -e

# Prawidłowa ścieżka do binarki Go (zakładając, że została umieszczona w głównym katalogu)
# Jeśli binarka jest w /portainer-deploy, użyj /portainer-deploy
BIN_PATH="/root/portainer-deploy"

# Weryfikacja: Upewnij się, że binarka istnieje
if [ ! -f "$BIN_PATH" ]; then
    echo "Error: Binary not found at $BIN_PATH. Check Dockerfile build path."
    exit 1
fi

# Lista argumentów, które będą budowane
ARGS=""

# Funkcja pomocnicza do warunkowego dodawania argumentów
set_arg() {
  # $1: nazwa flagi (np. --api-key)
  # $2: wartość zmiennej wejściowej (np. $INPUT_API_KEY)
  if [ -n "$2" ]; then
    # -n sprawdza, czy ciąg nie jest pusty
    ARGS="$ARGS $1=\"$2\""
  fi
}

# ------------------- Uwierzytelnianie -------------------
# Flagi API Key, User, Pass są opcjonalne (przekazujemy tylko, jeśli nie są puste)
set_arg "--api-key" "$INPUT_API_KEY"
set_arg "--username" "$INPUT_USERNAME"
set_arg "--password" "$INPUT_PASSWORD"

# ------------------- Deployment / Stack -------------------
# Używamy prostego przekazania dla wymaganych / z domyślnymi wartościami
ARGS="$ARGS --portainer-url=\"$INPUT_PORTAINER_HOST\""
ARGS="$ARGS --stack-name=\"$INPUT_STACK_NAME\""
ARGS="$ARGS --deployment-method=\"$INPUT_DEPLOYMENT_METHOD\""
ARGS="$ARGS --endpoint-name=\"$INPUT_ENDPOINT_NAME\"" # POPRAWIONA FLAGA

# ------------------- Tryb Repository (Opcjonalne) -------------------
set_arg "--repository-url" "$INPUT_REPOSITORY_URL"
set_arg "--repository-reference" "$INPUT_REPOSITORY_REFERENCE"
set_arg "--repository-username" "$INPUT_REPOSITORY_USERNAME"
set_arg "--repository-password" "$INPUT_REPOSITORY_PASSWORD"
set_arg "--compose-file-path" "$INPUT_COMPOSE_FILE_PATH"

# ------------------- Tryb String (Opcjonalne) -------------------
set_arg "--stack-file" "$INPUT_STACK_FILE"

# ------------------- Opcje -------------------
set_arg "--environment-variables" "$INPUT_ENVIRONMENT_VARIABLES"
set_arg "--auto-update-interval" "$INPUT_AUTO_UPDATE_INTERVAL"

set_arg "--prune" "$INPUT_PRUNE"
set_arg "--pull-image" "$INPUT_PULL_IMAGE"
set_arg "--use-https" "$INPUT_USE_HTTPS"
set_arg "--auto-update" "$INPUT_AUTO_UPDATE"

# ------------------- Kontrola Dostępu -------------------
set_arg "--access" "$INPUT_ACCESS"
set_arg "--teams" "$INPUT_TEAMS" # Nazwa flagi to --teams (lub --team, w zależności od binarki Go)

# ------------------- WYKONANIE -------------------
echo "Executing: $BIN_PATH $ARGS"
eval "$BIN_PATH $ARGS"