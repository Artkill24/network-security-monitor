#!/bin/bash

# Colori
CYAN='\033[0;36m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m'

show_logo() {
    clear
    echo -e "${CYAN}"
    cat << "LOGO"
████████████████████████████████████████████████████████████████
██╗░░██╗██████╗░██████╗░██████╗░███████╗███████╗██╗██╗░░██╗██╗  █
██║░██╔╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██║██║░██╔╝██║  █
█████╔╝░██████╔╝██████╔╝██████╔╝█████╗░░█████╗░░██║█████╔╝░██║  █
██╔═██╗░██╔══██╗██╔══██╗██╔══██╗██╔══╝░░██╔══╝░░██║██╔═██╗░██║  █
██║░╚██╗██║░░██║██║░░██║██║░░██║███████╗███████╗██║██║░╚██╗██║  █
╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚══════╝╚═╝╚═╝░░╚═╝╚═╝  █
████████████████████████████████████████████████████████████████
LOGO

    echo -e "${NC}"
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${YELLOW}🔒 NETWORK SECURITY MONITOR${NC} ${PURPLE}v2.0${NC}                      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} ${GREEN}Advanced Real-Time Network Security Monitoring System${NC}     ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} ${CYAN}🛡️  Real-time Threat Detection${NC}                            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} ${CYAN}📊 Interactive Web Dashboard${NC}                              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} ${CYAN}🌐 GitHub Codespaces Optimized${NC}                           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} ${CYAN}⚡ Zero-Click Setup & Deploy${NC}                              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} ${YELLOW}Author:${NC} Artkill24 ${YELLOW}|${NC} ${YELLOW}License:${NC} MIT ${YELLOW}|${NC} ${YELLOW}Support:${NC} paypal.me/saadkai ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}🚀 Ready to secure your network! Use: ${YELLOW}./scripts/quick-commands.sh help${NC}"
    echo ""
}

# Mostra logo se script chiamato direttamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    show_logo
fi
