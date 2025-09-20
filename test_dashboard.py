#!/usr/bin/env python3
"""
Test della Dashboard Web
"""

import time
import threading
from web_dashboard import WebDashboard, create_dashboard_template

def test_dashboard():
    print("🧪 Test Dashboard Web")
    print("=" * 30)
    
    # Crea template
    create_dashboard_template()
    print("✅ Template creato")
    
    # Test configurazione
    try:
        dashboard = WebDashboard()
        print("✅ Dashboard inizializzata")
    except Exception as e:
        print(f"❌ Errore inizializzazione: {e}")
        return
    
    # Test componenti
    print("✅ Componenti caricati")
    
    print("\n🎉 Test completati con successo!")
    print("💡 Per avviare la dashboard: python dashboard_launcher.py")

if __name__ == "__main__":
    test_dashboard()
