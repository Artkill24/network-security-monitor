import os
import json
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque, defaultdict
import threading

class AlertSystem:
    def __init__(self, config):
        self.config = config
        self.is_enabled = True
        self.alert_queue = deque(maxlen=1000)
        self.alert_count = defaultdict(int)
        self.last_alert_time = defaultdict(datetime)
        
        # Setup logging
        self._setup_logging()
        
        # Rate limiting
        self.max_alerts_per_minute = config['alerts'].get('max_alerts_per_minute', 10)
        self.alert_timestamps = deque(maxlen=self.max_alerts_per_minute)
        
        # Thread lock
        self.alert_lock = threading.Lock()

    def _setup_logging(self):
        """Configura il sistema di logging"""
        log_dir = os.path.dirname(self.config['alerts']['log_file'])
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Configura logger principale
        self.logger = logging.getLogger('SecurityMonitor')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(self.config['alerts']['log_file'])
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Evita handler duplicati
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            if self.config['alerts']['console_output']:
                self.logger.addHandler(console_handler)

    def send_alert(self, alert_data):
        """Invia un alert attraverso tutti i canali configurati"""
        if not self.is_enabled:
            return
        
        with self.alert_lock:
            # Rate limiting check
            if not self._check_rate_limit():
                self._log_rate_limit_exceeded()
                return
            
            # Deduplica alert simili
            if self._is_duplicate_alert(alert_data):
                return
            
            # Processa l'alert
            processed_alert = self._process_alert(alert_data)
            self.alert_queue.append(processed_alert)
            
            # Invia attraverso i canali configurati
            self._send_console_alert(processed_alert)
            self._log_alert(processed_alert)
            
            if self.config['alerts']['email_notifications']:
                self._send_email_alert(processed_alert)

    def _check_rate_limit(self):
        """Controlla se abbiamo superato il rate limit"""
        current_time = datetime.now()
        
        # Rimuovi timestamp vecchi (oltre 1 minuto)
        while (self.alert_timestamps and 
               current_time - self.alert_timestamps[0] > timedelta(minutes=1)):
            self.alert_timestamps.popleft()
        
        # Controlla se possiamo inviare l'alert
        if len(self.alert_timestamps) >= self.max_alerts_per_minute:
            return False
        
        self.alert_timestamps.append(current_time)
        return True

    def _log_rate_limit_exceeded(self):
        """Log quando il rate limit è superato"""
        self.logger.warning("⚠️  Rate limit superato per gli alert")

    def _is_duplicate_alert(self, alert_data):
        """Controlla se l'alert è un duplicato di uno recente"""
        if not self.alert_queue:
            return False
        
        # Controlla gli ultimi 10 alert
        for recent_alert in list(self.alert_queue)[-10:]:
            if (recent_alert.get('source_ip') == alert_data.get('source_ip') and
                recent_alert.get('threat_type') == alert_data.get('threat_type')):
                
                # Se è passato meno di 1 minuto, è un duplicato
                time_diff = datetime.now() - datetime.strptime(
                    recent_alert['timestamp'], '%Y-%m-%d %H:%M:%S'
                )
                if time_diff < timedelta(minutes=1):
                    return True
        
        return False

    def _process_alert(self, alert_data):
        """Processa e arricchisce i dati dell'alert"""
        processed = alert_data.copy()
        
        # Aggiunge timestamp se mancante
        if 'timestamp' not in processed:
            processed['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Aggiunge ID univoco
        processed['alert_id'] = self._generate_alert_id()
        
        # Determina livello se mancante
        if 'level' not in processed:
            processed['level'] = self._determine_alert_level(processed)
        
        # Aggiunge contesto geografico (se disponibile)
        if 'source_ip' in processed:
            processed['geo_info'] = self._get_geo_info(processed['source_ip'])
        
        # Conta gli alert per tipo
        alert_type = processed.get('threat_type', 'unknown')
        self.alert_count[alert_type] += 1
        
        return processed

    def _generate_alert_id(self):
        """Genera un ID univoco per l'alert"""
        import hashlib
        import uuid
        
        unique_string = f"{datetime.now().isoformat()}{uuid.uuid4()}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:8]

    def _determine_alert_level(self, alert_data):
        """Determina il livello di severità dell'alert"""
        threat_type = alert_data.get('threat_type', '').lower()
        
        if any(keyword in threat_type for keyword in ['ddos', 'critical', 'breach']):
            return 'critical'
        elif any(keyword in threat_type for keyword in ['brute', 'scan', 'attack']):
            return 'warning'
        elif any(keyword in threat_type for keyword in ['suspicious', 'anomaly']):
            return 'info'
        else:
            return 'info'

    def _get_geo_info(self, ip):
        """Ottiene informazioni geografiche per un IP (placeholder)"""
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.'):
            return {'country': 'Local', 'city': 'LAN'}
        
        return {'country': 'Unknown', 'city': 'Unknown'}

    def _send_console_alert(self, alert):
        """Invia alert sulla console"""
        if not self.config['alerts']['console_output']:
            return
        
        level_icons = self.config['alerts']['alert_levels']
        icon = level_icons.get(alert['level'], '⚠️')
        
        alert_msg = self._format_alert_message(alert, icon)
        print(alert_msg)

    def _format_alert_message(self, alert, icon="🚨"):
        """Formatta il messaggio di alert"""
        lines = [
            f"{icon} SECURITY ALERT [{alert['alert_id']}]",
            f"Time: {alert['timestamp']}",
            f"Type: {alert.get('threat_type', 'Unknown')}",
            f"Source: {alert.get('source_ip', 'Unknown')}"
        ]
        
        if 'details' in alert:
            lines.append(f"Details: {alert['details']}")
        
        if 'geo_info' in alert:
            geo = alert['geo_info']
            lines.append(f"Location: {geo['city']}, {geo['country']}")
        
        return "\n".join(lines) + "\n" + "="*50

    def _log_alert(self, alert):
        """Registra l'alert nei log"""
        log_entry = {
            'alert_id': alert['alert_id'],
            'timestamp': alert['timestamp'],
            'level': alert['level'],
            'threat_type': alert.get('threat_type'),
            'source_ip': alert.get('source_ip'),
            'details': alert.get('details'),
            'blocked': alert.get('blocked', False)
        }
        
        log_message = f"ALERT: {json.dumps(log_entry, ensure_ascii=False)}"
        
        if alert['level'] == 'critical':
            self.logger.critical(log_message)
        elif alert['level'] == 'warning':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)

    def _send_email_alert(self, alert):
        """Invia alert via email (se configurato)"""
        try:
            # Configurazione email (da aggiungere al config)
            email_config = self.config.get('email', {})
            if not email_config:
                return
            
            smtp_server = email_config.get('smtp_server')
            smtp_port = email_config.get('smtp_port', 587)
            username = email_config.get('username')
            password = email_config.get('password')
            to_email = email_config.get('to_email')
            
            if not all([smtp_server, username, password, to_email]):
                return
            
            # Crea messaggio email
            msg = MIMEMultipart()
            msg['From'] = username
            msg['To'] = to_email
            msg['Subject'] = f"Security Alert: {alert.get('threat_type', 'Unknown Threat')}"
            
            body = self._format_email_body(alert)
            msg.attach(MIMEText(body, 'plain'))
            
            # Invia email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            
            text = msg.as_string()
            server.sendmail(username, to_email, text)
            server.quit()
            
            self.logger.info(f"Email alert inviato per {alert['alert_id']}")
            
        except Exception as e:
            self.logger.error(f"Errore nell'invio email: {e}")

    def _format_email_body(self, alert):
        """Formatta il corpo dell'email"""
        return f"""
Security Alert Report
====================

Alert ID: {alert['alert_id']}
Timestamp: {alert['timestamp']}
Severity: {alert['level'].upper()}

Threat Information:
- Type: {alert.get('threat_type', 'Unknown')}
- Source IP: {alert.get('source_ip', 'Unknown')}
- Status: {'BLOCKED' if alert.get('blocked') else 'MONITORING'}

Details:
{json.dumps(alert.get('details', {}), indent=2)}

Geographic Information:
{json.dumps(alert.get('geo_info', {}), indent=2)}

---
Network Security Monitor
Generated automatically - Do not reply
        """.strip()

    def get_recent_alerts(self, count=10):
        """Restituisce gli alert recenti"""
        with self.alert_lock:
            return list(self.alert_queue)[-count:]

    def get_alert_statistics(self):
        """Restituisce statistiche sugli alert"""
        with self.alert_lock:
            total_alerts = len(self.alert_queue)
            
            # Conta per livello
            level_counts = defaultdict(int)
            for alert in self.alert_queue:
                level_counts[alert.get('level', 'unknown')] += 1
            
            # Alert nelle ultime 24 ore
            yesterday = datetime.now() - timedelta(days=1)
            recent_alerts = [
                alert for alert in self.alert_queue
                if datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S') > yesterday
            ]
            
            return {
                'total_alerts': total_alerts,
                'alerts_24h': len(recent_alerts),
                'by_level': dict(level_counts),
                'by_type': dict(self.alert_count),
                'rate_limited': len(self.alert_timestamps) >= self.max_alerts_per_minute
            }

    def enable(self):
        """Abilita il sistema di alert"""
        self.is_enabled = True
        self.logger.info("Sistema di alert abilitato")

    def disable(self):
        """Disabilita il sistema di alert"""
        self.is_enabled = False
        self.logger.info("Sistema di alert disabilitato")

    def test_alert(self):
        """Invia un alert di test"""
        test_alert = {
            'threat_type': 'Test Alert',
            'source_ip': '127.0.0.1',
            'details': {'message': 'Questo è un alert di test'},
            'level': 'info'
        }
        
        self.send_alert(test_alert)
        print("✅ Alert di test inviato")
