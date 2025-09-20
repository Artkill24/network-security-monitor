#!/usr/bin/env python3
"""
Network Security Monitor
Un tool per monitorare la sicurezza di rete in tempo reale
"""

import argparse
import sys
import json
import signal
import threading
from datetime import datetime
from src.network_monitor import NetworkMonitor
from src.threat_detector import ThreatDetector
from src.alert_system import AlertSystem

class SecurityMonitor:
    def __init__(self, config_path="config/settings.json"):
        self.config = self.load_config(config_path)
        self.running = False
        
        # Inizializza i componenti
        self.network_monitor = NetworkMonitor(self.config)
        self.threat_detector = ThreatDetector(self.config)
        self.alert_system = AlertSystem(self.config)
        
        # Setup signal handlers per shutdown pulito
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def load_config(self, config_path):
        """Carica la configurazione dal file JSON"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"⚠️  File di configurazione {config_path} non trovato. Uso configurazione di default.")
            return self.get_default_config()
        except json.JSONDecodeError as e:
            print(f"❌ Errore nel parsing del file di configurazione: {e}")
            sys.exit(1)

    def get_default_config(self):
        """Configurazione di default"""
        return {
            "monitoring": {
                "interface": "auto",
                "scan_interval": 5,
                "port_scan_detection": True,
                "suspicious_connections": True
            },
            "detection": {
                "max_connections_per_ip": 100,
                "port_scan_threshold": 10,
                "suspicious_ports": [22, 23, 3389, 5900],
                "blocked_ips": []
            },
            "alerts": {
                "console_output": True,
                "log_file": "logs/security.log",
                "email_notifications": False
            }
        }

    def signal_handler(self, signum, frame):
        """Gestisce i segnali per shutdown pulito"""
        print(f"\n🛑 Ricevuto segnale {signum}. Arresto in corso...")
        self.stop()

    def start(self):
        """Avvia il monitoraggio di sicurezza"""
        print("🔒 Network Security Monitor - Avvio...")
        print(f"⏰ Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        self.running = True
        
        try:
            # Avvia i thread per i diversi componenti
            monitor_thread = threading.Thread(target=self.network_monitor.start_monitoring)
            detector_thread = threading.Thread(target=self.threat_detector.start_detection)
            
            monitor_thread.daemon = True
            detector_thread.daemon = True
            
            monitor_thread.start()
            detector_thread.start()
            
            print("✅ Monitoraggio avviato! Premi Ctrl+C per fermare.")
            
            # Mantieni il programma in esecuzione
            while self.running:
                threading.Event().wait(1)
                
        except Exception as e:
            print(f"❌ Errore durante l'avvio: {e}")
            self.stop()

    def stop(self):
        """Ferma il monitoraggio"""
        self.running = False
        self.network_monitor.stop()
        self.threat_detector.stop()
        print("🔒 Monitoraggio arrestato.")

    def show_status(self):
        """Mostra lo status del sistema"""
        print("\n📊 STATUS DEL SISTEMA")
        print("=" * 40)
        print(f"🔍 Network Monitor: {'🟢 Attivo' if self.network_monitor.is_running else '🔴 Inattivo'}")
        print(f"🛡️  Threat Detector: {'🟢 Attivo' if self.threat_detector.is_running else '🔴 Inattivo'}")
        print(f"📢 Alert System: {'🟢 Attivo' if self.alert_system.is_enabled else '🔴 Inattivo'}")

def main():
    parser = argparse.ArgumentParser(description="Network Security Monitor")
    parser.add_argument("--config", "-c", default="config/settings.json",
                      help="Percorso del file di configurazione")
    parser.add_argument("--status", "-s", action="store_true",
                      help="Mostra lo status del sistema")
    parser.add_argument("--verbose", "-v", action="store_true",
                      help="Output verboso")
    
    args = parser.parse_args()
    
    # Crea l'istanza del monitor
    monitor = SecurityMonitor(args.config)
    
    if args.status:
        monitor.show_status()
        return
    
    if args.verbose:
        print("🔧 Modalità verbosa attivata")
    
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\n👋 Arrivederci!")
    except Exception as e:
        print(f"❌ Errore fatale: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()