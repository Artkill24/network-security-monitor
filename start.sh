#!/bin/bash
# Script di avvio rapido per Network Security Monitor

cd "$(dirname "$0")"

# Attiva virtual environment se esiste
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Controlla privilegi per packet sniffing
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Avviso: Eseguire come root per packet sniffing completo"
    echo "   Per privilegi completi: sudo ./start.sh"
    echo ""
fi

# Avvia il monitor
python main.py "$@"
