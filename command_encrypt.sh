#!/bin/bash

# === Utilisation
usage() {
    echo "Usage: $0 -i <message.txt> -o <secure_message.json>"
    exit 1
}

# === Valeurs par défaut
INPUT_FILE="message.txt"
OUTPUT_FILE="secure_message.json"

# === Lecture des arguments
while getopts ":i:o:" opt; do
  case $opt in
    i) INPUT_FILE="$OPTARG" ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    *) usage ;;
  esac
done

# === Vérification fichier d'entrée
if [ ! -f "$INPUT_FILE" ]; then
    echo "❌ Le fichier '$INPUT_FILE' est introuvable."
    exit 1
fi

# === Lancement du chiffrement
echo "🔐 Chiffrement du fichier '$INPUT_FILE'..."
python3 encrypt.py "$INPUT_FILE" "$OUTPUT_FILE"

# === Fin
echo "✅ Résultat chiffré sauvegardé dans '$OUTPUT_FILE'"
