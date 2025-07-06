#!/bin/bash

# === Utilisation
usage() {
    echo "Usage: $0 -i <secure_message.json>"
    exit 1
}

# === Valeur par défaut
JSON_FILE="secure_message.json"

# === Lecture des arguments
while getopts ":i:" opt; do
  case $opt in
    i) JSON_FILE="$OPTARG" ;;
    *) usage ;;
  esac
done

# === Vérification du fichier
if [ ! -f "$JSON_FILE" ]; then
    echo "❌ Le fichier '$JSON_FILE' est introuvable."
    exit 1
fi

# === Lancement du déchiffrement
echo "🔓 Déchiffrement du fichier '$JSON_FILE'..."
python3 decrypt.py "$JSON_FILE"
