import time
import threading
import psutil
import netifaces
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
import socket

class NetworkMonitor:
    def __init__(self, config):
        self.config = config
        self.is_running = False
        self.connection_stats = defaultdict(int)
        self.port_access_stats = defaultdict(lambda: defaultdict(int))
        self.packet_count = 0
        self.start_time = None
        self.interface = self._get_interface()
        
        # Statistiche in tempo reale
        self.recent_connections = deque(maxlen=1000)
        self.suspicious_ips = set()
        
        # Thread lock per thread safety
        self.stats_lock = threading.Lock()

    def _get_interface(self):
        """Rileva automaticamente l'interfaccia di rete principale"""
        if self.config['monitoring']['interface'] != 'auto':
            return self.config['monitoring']['interface']
        
        try:
            # Trova l'interfaccia con gateway di default
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {})
            if netifaces.AF_INET in default_gateway:
                return default_gateway[netifaces.AF_INET][1]
        except:
            pass
        
        # Fallback: prima interfaccia non loopback
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface.startswith(('eth', 'wlan', 'en')):
                return iface
        
        return None

    def start_monitoring(self):
        """Avvia il monitoraggio del traffico di rete"""
        if self.is_running:
            return
        
        self.is_running = True
        self.start_time = datetime.now()
        
        print(f"🔍 Avvio monitoraggio su interfaccia: {self.interface}")
        
        if not self.interface:
            print("❌ Nessuna interfaccia di rete trovata!")
            return
        
        try:
            # Avvia il monitoraggio delle connessioni di sistema
            system_thread = threading.Thread(target=self._monitor_system_connections)
            system_thread.daemon = True
            system_thread.start()
            
            # Avvia il packet sniffing (richiede privilegi root)
            try:
                sniff(iface=self.interface, prn=self._process_packet, 
                     filter="ip", store=False, stop_filter=lambda x: not self.is_running)
            except PermissionError:
                print("⚠️  Packet sniffing richiede privilegi root. Continuo con monitoraggio connessioni...")
                self._monitor_without_sniffing()
                
        except Exception as e:
            print(f"❌ Errore nel monitoraggio: {e}")
            self.is_running = False

    def _monitor_system_connections(self):
        """Monitora le connessioni di sistema usando psutil"""
        while self.is_running:
            try:
                connections = psutil.net_connections(kind='inet')
                
                with self.stats_lock:
                    for conn in connections:
                        if conn.raddr:  # Connessione remota attiva
                            remote_ip = conn.raddr.ip
                            remote_port = conn.raddr.port
                            local_port = conn.laddr.port if conn.laddr else 0
                            
                            # Aggiorna statistiche
                            self.connection_stats[remote_ip] += 1
                            self.port_access_stats[remote_ip][remote_port] += 1
                            
                            # Salva connessione recente
                            connection_info = {
                                'timestamp': datetime.now(),
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'local_port': local_port,
                                'status': conn.status,
                                'type': 'system'
                            }
                            self.recent_connections.append(connection_info)
                            
                            # Controlla soglie sospette
                            self._check_suspicious_activity(remote_ip, remote_port)
                
                time.sleep(self.config['monitoring']['scan_interval'])
                
            except Exception as e:
                print(f"⚠️  Errore nel monitoraggio connessioni: {e}")
                time.sleep(5)

    def _monitor_without_sniffing(self):
        """Monitoraggio senza packet capture"""
        while self.is_running:
            try:
                # Monitora statistiche di rete
                net_io = psutil.net_io_counters()
                if hasattr(self, 'last_net_io'):
                    bytes_sent = net_io.bytes_sent - self.last_net_io.bytes_sent
                    bytes_recv = net_io.bytes_recv - self.last_net_io.bytes_recv
                    
                    if bytes_sent > 0 or bytes_recv > 0:
                        print(f"📊 Traffico: ⬆️ {self._format_bytes(bytes_sent)} ⬇️ {self._format_bytes(bytes_recv)}")
                
                self.last_net_io = net_io
                time.sleep(self.config['monitoring']['scan_interval'])
                
            except Exception as e:
                print(f"⚠️  Errore nel monitoraggio: {e}")
                time.sleep(5)

    def _process_packet(self, packet):
        """Processa un singolo pacchetto catturato"""
        if not self.is_running:
            return
        
        self.packet_count += 1
        
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Analizza il protocollo
                protocol = "Unknown"
                src_port = dst_port = 0
                
                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif ICMP in packet:
                    protocol = "ICMP"
                
                # Salva informazioni del pacchetto
                packet_info = {
                    'timestamp': datetime.now(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'size': len(packet),
                    'type': 'packet'
                }
                
                with self.stats_lock:
                    self.recent_connections.append(packet_info)
                    
                    # Aggiorna statistiche per IP esterni
                    if not self._is_local_ip(src_ip):
                        self.connection_stats[src_ip] += 1
                        if dst_port > 0:
                            self.port_access_stats[src_ip][dst_port] += 1
                        self._check_suspicious_activity(src_ip, dst_port)
                        
        except Exception as e:
            print(f"⚠️  Errore nel processing del pacchetto: {e}")

    def _check_suspicious_activity(self, ip, port):
        """Controlla attività sospette"""
        # Controlla troppe connessioni da un singolo IP
        if self.connection_stats[ip] > self.config['detection']['max_connections_per_ip']:
            self.suspicious_ips.add(ip)
            self._alert_suspicious_activity(ip, "Troppe connessioni", self.connection_stats[ip])
        
        # Controlla porte sospette
        if port in self.config['detection']['suspicious_ports']:
            self._alert_suspicious_activity(ip, f"Accesso a porta sospetta", port)
        
        # Controlla possibile port scan
        unique_ports = len(self.port_access_stats[ip])
        if unique_ports > self.config['detection']['port_scan_threshold']:
            self.suspicious_ips.add(ip)
            self._alert_suspicious_activity(ip, "Possibile port scan", unique_ports)

    def _alert_suspicious_activity(self, ip, reason, details):
        """Genera un alert per attività sospetta"""
        alert = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': ip,
            'reason': reason,
            'details': details,
            'level': 'warning'
        }
        
        print(f"🟡 ALERT: {ip} - {reason} ({details})")
        
        # Qui potresti integrare con il sistema di alert
        # self.alert_system.send_alert(alert)

    def _is_local_ip(self, ip):
        """Controlla se un IP è locale"""
        local_ranges = [
            '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
            '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
            '172.29.', '172.30.', '172.31.'
        ]
        return any(ip.startswith(prefix) for prefix in local_ranges)

    def _format_bytes(self, bytes_value):
        """Formatta i byte in formato leggibile"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} TB"

    def get_stats(self):
        """Restituisce le statistiche attuali"""
        with self.stats_lock:
            uptime = datetime.now() - self.start_time if self.start_time else None
            
            return {
                'uptime': str(uptime).split('.')[0] if uptime else "Non avviato",
                'total_packets': self.packet_count,
                'unique_ips': len(self.connection_stats),
                'suspicious_ips': len(self.suspicious_ips),
                'recent_connections': len(self.recent_connections),
                'top_ips': dict(sorted(self.connection_stats.items(), 
                                     key=lambda x: x[1], reverse=True)[:10])
            }

    def stop(self):
        """Ferma il monitoraggio"""
        print("🛑 Arresto monitoraggio di rete...")
        self.is_running = False