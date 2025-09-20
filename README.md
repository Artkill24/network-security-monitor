# 🔒 Network Security Monitor

Un tool completo per il monitoraggio della sicurezza di rete in tempo reale, progettato per rilevare e bloccare attività sospette e potenziali minacce.

## ✨ Caratteristiche

- **Monitoraggio di Rete in Tempo Reale**: Analisi del traffico di rete e delle connessioni
- **Rilevamento Minacce Intelligente**: Algoritmi per identificare brute force, port scan, e anomalie
- **Sistema di Alert Avanzato**: Notifiche immediate con logging e opzioni email
- **Threat Intelligence**: Aggiornamento automatico delle blacklist
- **Interfaccia da Terminale**: Controllo completo via CLI
- **Configurazione Flessibile**: File JSON per personalizzare ogni aspetto

## 🚀 Installazione Rapida

### 1. Clona il Repository

```bash
git clone https://github.com/tuousername/network-security-monitor.git
cd network-security-monitor
```

### 2. Installa le Dipendenze

```bash
pip install -r requirements.txt
```

### 3. Crea le Directory

```bash
mkdir -p logs config
```

### 4. Avvia il Monitor

```bash
# Modalità standard
python main.py

# Con configurazione personalizzata
python main.py --config config/settings.json

# Modalità verbosa
python main.py --verbose
```

## 📋 Requisiti di Sistema

- **Python**: 3.7+
- **Sistema Operativo**: Linux, macOS, Windows
- **Privilegi**: Root/Administrator per packet sniffing completo
- **RAM**: Minimo 512MB
- **Dipendenze**: Vedi `requirements.txt`

## ⚙️ Configurazione

Il file `config/settings.json` permette di personalizzare ogni aspetto:

```json
{
  "monitoring": {
    "interface": "auto",
    "scan_interval": 5,
    "port_scan_detection": true,
    "suspicious_connections": true
  },
  "detection": {
    "max_connections_per_ip": 100,
    "port_scan_threshold": 10,
    "suspicious_ports": [22, 23, 3389, 5900],
    "blocked_ips": []
  },
  "alerts": {
    "console_output": true,
    "log_file": "logs/security.log",
    "email_notifications": false
  }
}
```

### Opzioni di Configurazione

#### Monitoraggio
- `interface`: Interfaccia di rete da monitorare ("auto" per rilevamento automatico)
- `scan_interval`: Intervallo di scansione in secondi
- `port_scan_detection`: Abilita rilevamento port scan
- `suspicious_connections`: Monitora connessioni sospette

#### Rilevamento
- `max_connections_per_ip`: Massimo numero di connessioni per IP
- `port_scan_threshold`: Soglia per rilevare port scan
- `suspicious_ports`: Lista porte da monitorare
- `blocked_ips`: IP da bloccare immediatamente

#### Alert
- `console_output`: Mostra alert sulla console
- `log_file`: File di log per gli alert
- `email_notifications`: Abilita notifiche email

## 🖥️ Utilizzo

### Comandi Base

```bash
# Avvia monitoraggio
python main.py

# Mostra status
python main.py --status

# Usa configurazione personalizzata
python main.py --config my_config.json

# Modalità verbosa
python main.py --verbose
```

### Durante l'Esecuzione

Il tool mostra informazioni in tempo reale:

```
🔒 Network Security Monitor - Avvio...
⏰ Timestamp: 2024-01-15 14:30:22
============================================================
🔍 Avvio monitoraggio su interfaccia: eth0
🛡️  Avvio Threat Detector...
✅ Monitoraggio avviato! Premi Ctrl+C per fermare.

🟡 ALERT: 192.168.1.100 - Troppe connessioni (150)
🔴 THREAT DETECTED: 10.0.0.50 - Port Scan Detected
🚫 IP BLOCKED: 10.0.0.50
```

### Tipologie di Alert

- 🔵 **Info**: Attività normale ma degna di nota
- 🟡 **Warning**: Attività sospetta che richiede attenzione
- 🔴 **Critical**: Minaccia attiva rilevata
- 🚫 **Blocked**: IP bloccato automaticamente

## 📊 Monitoraggio e Statistiche

### Tipi di Minacce Rilevate

1. **Brute Force Attack**: Tentativi di login multipli falliti
2. **Port Scan**: Scansione sistematica delle porte
3. **DDoS Patterns**: Pattern di traffico da attacco distribuito
4. **Suspicious Processes**: Processi potenzialmente malevoli
5. **Anomalous Connections**: Connessioni a porte inusuali

### File di Log

Il sistema genera log dettagliati in:

- `logs/security.log`: Log principale degli alert
- `logs/daily_reports/`: Report giornalieri automatici

Formato log:
```
2024-01-15 14:35:22 | WARNING | ALERT: {"alert_id": "a1b2c3d4", "threat_type": "Port Scan", "source_ip": "192.168.1.50"}
```

## 🛡️ Funzionalità di Sicurezza

### Rilevamento Automatico

- **Port Scanning**: Rileva scansioni sistematiche delle porte
- **Brute Force**: Identifica tentativi di autenticazione multipli
- **Traffic Anomalies**: Analizza pattern di traffico anomali
- **Process Monitoring**: Monitora processi sospetti

### Blocco Automatico

Il sistema può bloccare automaticamente IP sospetti:

- Soglie configurabili per ogni tipo di minaccia
- Whitelist per IP fidati
- Blocco temporaneo o permanente

### Threat Intelligence

- Aggiornamento automatico delle blacklist pubbliche
- Database di IP malevoli noti
- Integrazione con feed di threat intelligence

## 🔧 Personalizzazione Avanzata

### Aggiungere Nuovi Rilevatori

Puoi estendere il `ThreatDetector` per nuove minacce:

```python
def _detect_custom_threat(self):
    # La tua logica personalizzata
    if suspicious_condition:
        self._trigger_threat_alert(ip, "Custom Threat", details)
```

### Notifiche Email

Configura le notifiche email aggiungendo al config:

```json
{
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "tuo@email.com",
    "password": "password",
    "to_email": "admin@azienda.com"
  }
}
```

### Script di Automazione

Crea script per automazione:

```bash
#!/bin/bash
# auto_start.sh
cd /path/to/security-monitor
python main.py --config production.json >> logs/startup.log 2>&1 &
```

## 🔍 Troubleshooting

### Problemi Comuni

**"Permission Denied" per packet sniffing**
```bash
# Esegui con privilegi root
sudo python main.py
```

**Interfaccia di rete non trovata**
```bash
# Specifica manualmente nel config
"interface": "eth0"
```

**Troppe notifiche**
```bash
# Aumenta la soglia nel config
"max_alerts_per_minute": 5
```

### Debug Mode

Per debugging dettagliato:

```bash
python main.py --verbose
```

### Log Analysis

Analizza i log con:

```bash
# Filtra alert critici
grep "CRITICAL" logs/security.log

# Conta alert per IP
grep -o '"source_ip": "[^"]*"' logs/security.log | sort | uniq -c
```

## 📈 Performance

### Ottimizzazione

- **Memoria**: ~50-100MB in uso normale
- **CPU**: <5% su sistema moderno
- **I/O**: Log rotazione automatica
- **Rete**: Impatto minimo sul traffico

### Scalabilità

Il tool può gestire:
- Reti fino a 1000+ dispositivi
- Migliaia di connessioni simultanee
- Centinaia di alert al minuto

## 🤝 Contribuire

### Come Contribuire

1. Fork del repository
2. Crea un branch per la feature: `git checkout -b feature/nuova-funzionalità`
3. Commit delle modifiche: `git commit -m 'Aggiungi nuova funzionalità'`
4. Push del branch: `git push origin feature/nuova-funzionalità`
5. Apri una Pull Request

### Reporting Bug

Usa le Issues di GitHub per segnalare bug, includendo:
- Versione del sistema operativo
- Versione Python
- Log di errore completo
- Passi per riprodurre

## 📄 Licenza

Questo progetto è rilasciato sotto licenza MIT. Vedi il file `LICENSE` per i dettagli.

## ⚠️ Disclaimer

Questo tool è progettato per scopi di sicurezza legittimi. L'utilizzo per attività illegali è vietato e non supportato. Utilizzare sempre in conformità con le leggi locali e le policy aziendali.

## 📞 Supporto

- **Issues**: [GitHub Issues](https://github.com/tuousername/network-security-monitor/issues)
- **Documentazione**: [Wiki del progetto](https://github.com/tuousername/network-security-monitor/wiki)
- **Sicurezza**: Per vulnerabilità, contatta privatamente

---

**Network Security Monitor** - Proteggendo la tua rete, un pacchetto alla volta 🛡️