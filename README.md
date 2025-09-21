# 🔒 Network Security Monitor

[![GitHub Codespaces](https://img.shields.io/badge/GitHub-Codespaces-blue.svg)](https://github.com/codespaces)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dashboard](https://img.shields.io/badge/Dashboard-Real--Time-green.svg)](http://localhost:5000)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-blue.svg)](https://paypal.me/saadkai)

> **Sistema avanzato di monitoraggio della sicurezza di rete in tempo reale, completamente ottimizzato per GitHub Codespaces con dashboard web interattiva**

## ⚡ Quick Start (30 secondi)

### 🚀 GitHub Codespaces - Zero Click Deploy
```bash
# 1. Click "Code" → "Codespaces" → "Create codespace on main"
# 2. Setup automatico (esegui nel terminale Codespaces):
./scripts/quick-commands.sh setup

# 3. Avvia dashboard web
./scripts/quick-commands.sh dashboard

# 4. Dashboard pronta su: http://localhost:5000
🌐 Dashboard Live Features
La dashboard è immediatamente operativa con:

📊 Grafici real-time del traffico di rete con Plotly.js
🔍 Monitoraggio connessioni attive in tempo reale
🚨 Sistema di alert con notifiche live via WebSocket
🛡️ Controlli interattivi per blocco IP istantaneo
📱 Design responsive ottimizzato per ogni dispositivo
🌙 Dark theme professionale per monitoring 24/7

✨ Caratteristiche Principali
��️ Security Monitoring Avanzato

Port Scan Detection: Algoritmi per identificare scansioni sistematiche
Brute Force Prevention: Monitora tentativi di login multipli e sospetti
Traffic Anomaly Analysis: AI per analizzare pattern di traffico anomali
Automatic IP Blocking: Sistema automatico di blocco IP malevoli
Threat Intelligence: Database minacce aggiornato in tempo reale
Process Monitoring: Controllo processi sospetti e malware

🌐 Dashboard Web Professionale

Modern UI/UX: Design gradiente blu professionale
Interactive Charts: Grafici Plotly.js con zoom, pan, export
Live WebSocket Updates: Aggiornamenti istantanei senza refresh
Mobile First: Responsive design per smartphone e tablet
Real-time Stats: Metriche live CPU, memoria, rete
Export Functions: PDF, JSON, CSV per report e analisi

📊 Sistema Alert Intelligente

Multi-Level Severity: Info 🔵, Warning 🟡, Critical 🔴, Blocked 🚫
Smart Notifications: Alert contestualizzati con dettagli tecnici
Rate Limiting: Controllo intelligente frequenza notifiche
Log Correlation: Correlazione eventi per identificare attacchi
Email Integration: Notifiche SMTP configurabili
Slack/Discord: Webhook per team collaboration

⚙️ Cloud-Native & Codespaces Optimized

Zero-Click Setup: Configurazione automatica completa
Instant Port Forwarding: Dashboard immediatamente accessibile
Cloud Performance: Threading ottimizzato per VM cloud
Auto-scaling: Adattamento automatico alle risorse disponibili
Container Ready: Supporto Docker e Kubernetes
CI/CD Ready: GitHub Actions preconfigurate

🛠️ Comandi Rapidi
ComandoDescrizioneOutput./scripts/quick-commands.sh setupSetup completo progetto✅ Environment pronto./scripts/quick-commands.sh dashboardAvvia dashboard web🌐 http://localhost:5000./scripts/quick-commands.sh startMonitor completo sicurezza🛡️ Full monitoring./scripts/quick-commands.sh testTest sistema e dipendenze🧪 Health check./scripts/quick-commands.sh helpLista completa comandi📋 Guida rapida
📋 Installazione Locale
Setup Tradizionale
bash# 1. Clone repository
git clone https://github.com/Artkill24/network-security-monitor.git
cd network-security-monitor

# 2. Virtual environment (raccomandato)
python -m venv venv
source venv/bin/activate  # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Setup progetto
./scripts/quick-commands.sh setup

# 5. Avvia dashboard
./scripts/quick-commands.sh dashboard
⚙️ Configurazione
📝 File Configurazione: config/settings.json
json{
  "monitoring": {
    "interface": "auto",
    "scan_interval": 10,
    "port_scan_detection": true,
    "suspicious_connections": true
  },
  "detection": {
    "max_connections_per_ip": 500,
    "port_scan_threshold": 15,
    "suspicious_ports": [22, 23, 25, 135, 139, 445, 993, 995, 3389, 5900],
    "blocked_ips": [],
    "whitelist_ips": ["127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"]
  },
  "alerts": {
    "console_output": true,
    "log_file": "logs/security.log",
    "email_notifications": false,
    "max_alerts_per_minute": 3
  },
  "dashboard": {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": true
  }
}
�� Testing
bash# Test rapido importazioni e configurazione
./scripts/quick-commands.sh test

# Test completo del sistema
python -c "
from src.network_monitor import NetworkMonitor
from src.threat_detector import ThreatDetector
from src.alert_system import AlertSystem
print('✅ Tutti i moduli funzionanti')
"

# Test dashboard endpoint
curl -s http://localhost:5000/api/stats
📊 Dashboard Features
🎯 Componenti Dashboard

📈 Statistiche Live

Minacce rilevate in tempo reale
IP bloccati automaticamente
Connessioni attive monitorate
Pacchetti analizzati


📋 Alert Recenti

Lista alert con timestamp
Livelli di severità colorati
Azioni rapide per blocco IP
Auto-refresh ogni 5 secondi


📊 Grafico Traffico Real-Time

Bytes sent/received
Aggiornamento ogni 2 secondi
Zoom e pan interattivi
Export dati grafici



🌐 URLs Dashboard

Dashboard Principale: http://localhost:5000
API Stats: http://localhost:5000/api/stats
API Alerts: http://localhost:5000/api/alerts
API Traffic: http://localhost:5000/api/traffic

🔒 Sicurezza

IP Whitelisting: Protezione IP fidati
Rate Limiting: Controllo frequenza alert
Input Validation: Validazione dati input
Secure Logging: Log sicuri senza dati sensibili
Process Isolation: Monitoraggio processi isolato

📈 Performance

Startup Time: ~5-10 secondi
Memory Usage: ~50-100MB baseline
CPU Usage: <5% su hardware moderno
Network Overhead: Minimale
Dashboard Response: <100ms

🤝 Contribuire

Fork del repository
Clone del fork
Branch feature: git checkout -b feature/nuova-funzionalita
Commit: git commit -m 'feat: aggiungi nuova funzionalità'
Push: git push origin feature/nuova-funzionalita
Pull Request via GitHub

💰 Supporta il Progetto
Se questo progetto ti è stato utile, considera una donazione:
Mostra immagine
Perché donare?

🛠️ Sviluppo Continuo: Nuove funzionalità e miglioramenti
🐛 Bug Fixes: Risoluzione rapida dei problemi
📚 Documentazione: Guide e tutorial aggiornati
🔒 Security Updates: Patch di sicurezza tempestive
🌐 Community Support: Supporto attivo agli utenti

📚 Links

📘 Repository: GitHub
🐛 Issues: Bug Reports & Feature Requests
🚀 Releases: Changelog & Downloads
💰 Donations: PayPal Support

📄 Licenza
Questo progetto è rilasciato sotto licenza MIT.
⚠️ Disclaimer
Questo tool è progettato per scopi di sicurezza legittimi. L'utilizzo per attività illegali è vietato. Utilizzare sempre in conformità con le leggi locali e le policy aziendali.

<div align="center">
🔒 Network Security Monitor
Proteggendo la tua rete, un pacchetto alla volta
Fatto con ❤️ per la community della sicurezza informatica
Ready for GitHub Codespaces 🚀 | Real-time Dashboard 📊 | Production Ready 🏭
Mostra immagine
Mostra immagine
</div>
