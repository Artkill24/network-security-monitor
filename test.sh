#!/bin/bash
# Script di test per Network Security Monitor

cd "$(dirname "$0")"

# Attiva virtual environment se esiste
if [ -d "venv" ]; then
    source venv/bin/activate
fi

echo "🧪 Test Network Security Monitor"
echo "==============================="

# Test configurazione
echo "📋 Test configurazione..."
python -c "
import json
try:
    with open('config/settings.json', 'r') as f:
        config = json.load(f)
    print('✅ Configurazione valida')
except Exception as e:
    print(f'❌ Errore configurazione: {e}')
    exit(1)
"

# Test import moduli
echo "📦 Test moduli..."
python -c "
try:
    from src import NetworkMonitor, ThreatDetector, AlertSystem
    print('✅ Moduli importati correttamente')
except Exception as e:
    print(f'❌ Errore import: {e}')
    exit(1)
"

# Test dipendenze
echo "🔧 Test dipendenze..."
python -c "
import sys
required = ['psutil', 'scapy', 'netifaces', 'colorama', 'requests', 'nmap', 'tabulate']
missing = []
for pkg in required:
    try:
        __import__(pkg)
    except ImportError:
        missing.append(pkg)

if missing:
    print(f'❌ Dipendenze mancanti: {missing}')
    exit(1)
else:
    print('✅ Tutte le dipendenze sono installate')
"

echo ""
echo "🎉 Tutti i test superati!"
echo "💡 Per avviare il monitor: ./start.sh"
echo "💡 Per aiuto: python main.py --help"
