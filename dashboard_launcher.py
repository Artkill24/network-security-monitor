#!/usr/bin/env python3
"""
Network Security Monitor - Dashboard Launcher
Avvia il sistema completo con dashboard web
"""

import threading
import time
import signal
import sys
from web_dashboard import WebDashboard, create_dashboard_template

def main():
    print("🚀 Avvio Network Security Monitor con Dashboard Web")
    print("=" * 60)
    
    # Crea template se non esiste
    create_dashboard_template()
    
    # Inizializza dashboard
    dashboard = WebDashboard()
    
    def signal_handler(signum, frame):
        print(f"\n🛑 Arresto sistema...")
        dashboard.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        print("🌐 Dashboard disponibile su:")
        print("   http://localhost:5000")
        print("   http://0.0.0.0:5000")
        print("\n📊 Aprire il browser all'indirizzo sopra per accedere alla dashboard")
        print("🔒 Premi Ctrl+C per fermare il sistema")
        print("\n" + "=" * 60)
        
        # Avvia dashboard (bloccante)
        dashboard.start(host='0.0.0.0', port=5000, debug=False)
        
    except Exception as e:
        print(f"❌ Errore: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
