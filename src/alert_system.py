import time
import threading
import requests
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
import subprocess
import re

class ThreatDetector:
    def __init__(self, config):
        self.config = config
        self.is_running = False
        
        # Tracking per diverse tipologie di attacco
        self.failed_login_attempts = defaultdict(lambda: deque(maxlen=100))
        self.port_scan_attempts = defaultdict(lambda: deque(maxlen=1000))
        self.brute_force_ips = set()
        self.blocked_ips = set(config['detection']['blocked_ips'])
        
        # Database minacce conosciute
        self.malicious_ips = set()
        self.threat_signatures = []
        
        # Statistiche
        self.threats_detected = 0
        self.threats_blocked = 0
        
        # Thread lock
        self.detector_lock = threading.Lock()

    def start_detection(self):
        """Avvia il sistema di rilevamento minacce"""
        if self.is_running:
            return
            
        self.is_running = True
        print("🛡️  Avvio Threat Detector...")
        
        # Avvia thread paralleli per diversi tipi di detection
        threads = [
            threading.Thread(target=self._monitor_system_logs),
            threading.Thread(target=self._monitor_network_anomalies),
            threading.Thread(target=self._update_threat_intelligence),
            threading.Thread(target=self._monitor_processes)
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        # Loop principale di detection
        self._main_detection_loop()

    def _main_detection_loop(self):
        """Loop principale per il rilevamento"""
        while self.is_running:
            try:
                self._analyze_recent_activity()
                self._check_threat_patterns()
                self._cleanup_old_data()
                
                time.sleep(self.config['monitoring']['scan_interval'])
                
            except Exception as e:
                print(f"⚠️  Errore nel threat detector: {e}")
                time.sleep(5)

    def _monitor_system_logs(self):
        """Monitora i log di sistema per attività sospette"""
        while self.is_running:
            try:
                # Monitora tentativi di login falliti (Linux)
                self._check_auth_logs()
                
                # Monitora log di rete
                self._check_network_logs()
                
                time.sleep(10)
                
            except Exception as e:
                print(f"⚠️  Errore nel monitoraggio log: {e}")
                time.sleep(30)

    def _check_auth_logs(self):
        """Controlla i log di autenticazione per brute force"""
        try:
            # Prova a leggere auth.log (richiede permessi)
            auth_patterns = [
                r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
                r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)",
                r"Connection closed by (\d+\.\d+\.\d+\.\d+)"
            ]
            
            try:
                result = subprocess.run(['tail', '-n', '50', '/var/log/auth.log'], 
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        for pattern in auth_patterns:
                            match = re.search(pattern, line)
                            if match:
                                ip = match.group(1)
                                self._record_failed_login(ip, line)
                                
            except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
                # Log non accessibili, usa metodi alternativi
                pass
                
        except Exception as e:
            print(f"⚠️  Errore nella lettura auth logs: {e}")

    def _record_failed_login(self, ip, log_entry):
        """Registra un tentativo di login fallito"""
        with self.detector_lock:
            timestamp = datetime.now()
            self.failed_login_attempts[ip].append({
                'timestamp': timestamp,
                'entry': log_entry
            })
            
            # Controlla se è brute force
            recent_attempts = [
                attempt for attempt in self.failed_login_attempts[ip]
                if timestamp - attempt['timestamp'] < timedelta(minutes=10)
            ]
            
            if len(recent_attempts) >= 5:  # 5 tentativi in 10 minuti
                self.brute_force_ips.add(ip)
                self._trigger_threat_alert(ip, "Brute Force Attack", {
                    'attempts': len(recent_attempts),
                    'timeframe': '10 minutes',
                    'type': 'authentication'
                })

    def _monitor_network_anomalies(self):
        """Monitora anomalie di rete"""
        while self.is_running:
            try:
                # Controlla connessioni anomale
                self._check_unusual_connections()
                
                # Controlla traffico anomalo
                self._check_traffic_patterns()
                
                time.sleep(15)
                
            except Exception as e:
                print(f"⚠️  Errore nel monitoraggio anomalie: {e}")
                time.sleep(30)

    def _check_unusual_connections(self):
        """Controlla connessioni inusuali"""
        try:
            # Usa netstat per controllare connessioni
            result = subprocess.run(['netstat', '-tuln'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                suspicious_ports = self.config['detection']['suspicious_ports']
                
                for line in result.stdout.split('\n'):
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            local_address = parts[3]
                            if ':' in local_address:
                                port = int(local_address.split(':')[-1])
                                if port in suspicious_ports:
                                    self._trigger_threat_alert(
                                        "localhost", 
                                        "Suspicious Port Open", 
                                        {'port': port, 'address': local_address}
                                    )
                                    
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError) as e:
            pass

    def _check_traffic_patterns(self):
        """Analizza pattern di traffico per anomalie"""
        try:
            # Simula analisi del traffico
            # In un'implementazione reale, analizzeresti i dati dal NetworkMonitor
            
            # Placeholder per analisi avanzate:
            # - Rilevamento DDoS
            # - Traffico verso domini sospetti
            # - Upload/download anomali
            
            pass
            
        except Exception as e:
            print(f"⚠️  Errore nell'analisi traffico: {e}")

    def _update_threat_intelligence(self):
        """Aggiorna il database delle minacce"""
        while self.is_running:
            try:
                print("🔄 Aggiornamento threat intelligence...")
                
                # Carica IP blacklist pubbliche (esempio)
                self._load_public_blacklists()
                
                # Ogni ora
                time.sleep(3600)
                
            except Exception as e:
                print(f"⚠️  Errore nell'aggiornamento threat intelligence: {e}")
                time.sleep(1800)  # Riprova dopo 30 minuti

    def _load_public_blacklists(self):
        """Carica blacklist pubbliche"""
        blacklist_urls = [
            # Esempio di feed pubblici (sostituisci con feed reali)
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        ]
        
        for url in blacklist_urls:
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    # Processa la blacklist
                    new_ips = self._parse_blacklist(response.text)
                    self.malicious_ips.update(new_ips)
                    print(f"✅ Caricati {len(new_ips)} IP dalla blacklist")
                    
            except requests.RequestException:
                print(f"⚠️  Impossibile caricare blacklist da {url}")

    def _parse_blacklist(self, content):
        """Parsa una blacklist e restituisce set di IP"""
        ips = set()
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Estrai IP (formato semplificato)
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    ips.add(line)
        return ips

    def _monitor_processes(self):
        """Monitora processi sospetti"""
        while self.is_running:
            try:
                # Lista processi sospetti
                suspicious_processes = [
                    'nc', 'netcat', 'nmap', 'hping3', 'tcpdump'
                ]
                
                result = subprocess.run(['ps', 'aux'], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        for proc in suspicious_processes:
                            if proc in line and 'root' not in line:
                                self._trigger_threat_alert(
                                    "localhost",
                                    "Suspicious Process",
                                    {'process': proc, 'details': line.strip()}
                                )
                
                time.sleep(30)
                
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

    def _analyze_recent_activity(self):
        """Analizza l'attività recente per pattern sospetti"""
        with self.detector_lock:
            # Analizza pattern di accesso
            self._detect_port_scans()
            self._detect_ddos_patterns()

    def _detect_port_scans(self):
        """Rileva possibili port scan"""
        current_time = datetime.now()
        
        for ip in list(self.port_scan_attempts.keys()):
            recent_scans = [
                scan for scan in self.port_scan_attempts[ip]
                if current_time - scan['timestamp'] < timedelta(minutes=5)
            ]
            
            if len(recent_scans) > self.config['detection']['port_scan_threshold']:
                self._trigger_threat_alert(ip, "Port Scan Detected", {
                    'scan_count': len(recent_scans),
                    'timeframe': '5 minutes'
                })

    def _detect_ddos_patterns(self):
        """Rileva possibili attacchi DDoS"""
        # Placeholder per rilevamento DDoS
        # Analizza volume di traffico, numero di connessioni, etc.
        pass

    def _check_threat_patterns(self):
        """Controlla pattern di minacce conosciute"""
        # Confronta attività con signature di minacce note
        pass

    def _cleanup_old_data(self):
        """Pulisce dati vecchi per evitare memory leak"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(hours=24)
        
        with self.detector_lock:
            # Pulisci failed login attempts vecchi
            for ip in list(self.failed_login_attempts.keys()):
                self.failed_login_attempts[ip] = deque([
                    attempt for attempt in self.failed_login_attempts[ip]
                    if attempt['timestamp'] > cutoff_time
                ], maxlen=100)
                
                if not self.failed_login_attempts[ip]:
                    del self.failed_login_attempts[ip]

    def _trigger_threat_alert(self, source_ip, threat_type, details):
        """Genera un alert per una minaccia rilevata"""
        with self.detector_lock:
            self.threats_detected += 1
            
            alert = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'source_ip': source_ip,
                'threat_type': threat_type,
                'details': details,
                'severity': self._calculate_severity(threat_type, details),
                'blocked': source_ip in self.blocked_ips
            }
            
            severity_icon = {
                'low': '🔵',
                'medium': '🟡', 
                'high': '🔴',
                'critical': '🚨'
            }.get(alert['severity'], '⚠️')
            
            print(f"{severity_icon} THREAT DETECTED: {source_ip} - {threat_type}")
            print(f"   Details: {details}")
            
            # Auto-block per minacce critiche
            if alert['severity'] in ['high', 'critical'] and source_ip not in self.blocked_ips:
                self._block_ip(source_ip)

    def _calculate_severity(self, threat_type, details):
        """Calcola la severità di una minaccia"""
        severity_map = {
            'Brute Force Attack': 'high',
            'Port Scan Detected': 'medium',
            'Suspicious Process': 'medium',
            'Suspicious Port Open': 'low',
            'DDoS Attack': 'critical'
        }
        return severity_map.get(threat_type, 'low')

    def _block_ip(self, ip):
        """Blocca un IP (simulato)"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.threats_blocked += 1
            print(f"🚫 IP BLOCKED: {ip}")
            
            # In un sistema reale, aggiungeresti regole firewall:
            # subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])

    def add_to_port_scan_tracking(self, ip, port):
        """Aggiunge un tentativo di port scan al tracking"""
        with self.detector_lock:
            self.port_scan_attempts[ip].append({
                'timestamp': datetime.now(),
                'port': port
            })

    def is_ip_blocked(self, ip):
        """Controlla se un IP è bloccato"""
        return ip in self.blocked_ips

    def get_threat_stats(self):
        """Restituisce statistiche sulle minacce"""
        with self.detector_lock:
            return {
                'threats_detected': self.threats_detected,
                'threats_blocked': self.threats_blocked,
                'blocked_ips_count': len(self.blocked_ips),
                'brute_force_ips': len(self.brute_force_ips),
                'malicious_ips_db': len(self.malicious_ips)
            }

    def stop(self):
        """Ferma il threat detector"""
        print("🛑 Arresto Threat Detector...")
        self.is_running = False