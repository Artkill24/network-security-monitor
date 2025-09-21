#!/bin/bash
# Network Security Monitor - Quick Commands

# Source logo functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/logo.sh"

# Colori
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_success() { echo -e "${GREEN}✅${NC} $1"; }
print_info() { echo -e "${CYAN}ℹ️${NC} $1"; }

case "${1:-help}" in
    "setup")
        show_logo
        print_step "🔧 Setup Network Security Monitor..."
        
        # Crea directory necessarie
        mkdir -p {logs,config,static/{css,js,images},templates,tests,docs}
        mkdir -p src/{core,utils,api,models}
        
        print_step "📦 Installazione dipendenze..."
        pip install --upgrade pip
        pip install -r requirements.txt
        
        # Crea config di default se non esiste
        if [ ! -f "config/settings.json" ]; then
            print_step "📝 Creazione configurazione..."
            cat > config/settings.json << 'CONF'
{
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
CONF
            print_success "Configurazione creata"
        fi
        
        print_success "Setup completato!"
        print_info "Prossimo passo: ./scripts/quick-commands.sh dashboard"
        ;;
        
    "dashboard")
        show_logo
        print_step "🌐 Avvio Dashboard Web..."
        print_info "Dashboard disponibile su: http://localhost:5000"
        cd "$(dirname "$0")/.."
        
        # Usa il file dashboard esistente
        if [ -f "dashboard_launcher.py" ]; then
            python dashboard_launcher.py
        elif [ -f "web_dashboard.py" ]; then
            python web_dashboard.py
        else
            python main.py --dashboard-only 2>/dev/null || echo "❌ File main.py non trovato"
        fi
        ;;
        
    "start")
        show_logo
        print_step "🚀 Avvio Network Security Monitor completo..."
        cd "$(dirname "$0")/.."
        python main.py "$@"
        ;;
        
    "test")
        show_logo
        print_step "🧪 Test rapido del sistema..."
        python -c "
import sys, os
sys.path.append('src')
sys.path.append('.')
try:
    # Test moduli esistenti
    from src.network_monitor import NetworkMonitor
    from src.threat_detector import ThreatDetector
    print('✅ Moduli importati correttamente')
    
    # Test config
    import json
    with open('config/settings.json') as f:
        config = json.load(f)
    print('✅ Configurazione OK')
    print('✅ Test completati con successo')
except Exception as e:
    print(f'⚠️  Errore: {e}')
    print('💡 Prova prima: ./scripts/quick-commands.sh setup')
"
        ;;
        
    "demo")
        show_logo
        print_step "🎮 Modalità Demo con dati simulati..."
        export NSM_DEMO_MODE=1
        cd "$(dirname "$0")/.."
        python web_dashboard.py
        ;;
        
    "logo")
        show_logo
        ;;
        
    "help"|*)
        show_logo
        echo -e "${YELLOW}Comandi disponibili:${NC}"
        echo ""
        echo -e "${CYAN}📦 Setup e Configurazione:${NC}"
        echo "  setup      - Setup completo progetto"
        echo "  test       - Test rapido sistema"
        echo ""
        echo -e "${CYAN}🚀 Avvio Applicazione:${NC}"
        echo "  dashboard  - Avvia dashboard web"
        echo "  start      - Avvia monitor completo"
        echo "  demo       - Modalità demo con dati simulati"
        echo ""
        echo -e "${CYAN}🎨 Utilità:${NC}"
        echo "  logo       - Mostra logo ASCII"
        echo "  help       - Mostra questo aiuto"
        echo ""
        echo -e "${CYAN}Esempi:${NC}"
        echo "  ./scripts/quick-commands.sh setup"
        echo "  ./scripts/quick-commands.sh dashboard"
        echo "  ./scripts/quick-commands.sh demo"
        echo ""
        ;;
esac
