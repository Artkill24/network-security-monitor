#!/bin/bash

# Network Security Monitor - Setup Script
# Automatizza l'installazione e configurazione iniziale

set -e

echo "🔒 Network Security Monitor - Setup"
echo "===================================="

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funzione per stampare messaggi colorati
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Controllo prerequisiti
print_status "Controllo prerequisiti..."

# Controlla Python
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 non trovato. Installare Python 3.7+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
print_success "Python $PYTHON_VERSION trovato"

# Controlla pip
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 non trovato. Installare pip"
    exit 1
fi

print_success "pip3 trovato"

# Crea directory necessarie
print_status "Creazione directory..."

directories=("logs" "config" "logs/daily_reports")
for dir in "${directories[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        print_success "Directory creata: $dir"
    else
        print_warning "Directory già esistente: $dir"
    fi
done

# Installa dipendenze
print_status "Installazione dipendenze..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
    print_success "Dipendenze installate"
else
    print_error "File requirements.txt non trovato"
    exit 1
fi

# Rende script eseguibili
print_status "Configurazione script..."
chmod +x start.sh test.sh setup.sh
print_success "Script resi eseguibili"

# Test rapido
print_status "Esecuzione test rapido..."
if python3 -c "import json; json.load(open('config/settings.json'))" 2>/dev/null; then
    print_success "Configurazione valida"
else
    print_error "Errore nella configurazione"
    exit 1
fi

echo ""
echo "🎉 Setup completato con successo!"
echo ""
echo "📋 Prossimi passi:"
echo "  1. Testa l'installazione: ./test.sh"
echo "  2. Avvia il monitor: ./start.sh"
echo "  3. Per aiuto: python3 main.py --help"
echo ""
echo "⚠️  Note importanti:"
echo "  - Per packet sniffing completo: sudo ./start.sh"
echo "  - Personalizza config/settings.json se necessario"
echo "  - I log sono salvati in logs/"
echo ""
print_success "Setup terminato! 🔒"
