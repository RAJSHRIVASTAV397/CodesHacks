#!/bin/bash

# CodesHacks Installation Script
# This script installs CodesHacks and all its dependencies

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Version information
PYTHON_MIN_VERSION="3.8.0"
SUBFINDER_VERSION="2.6.3"
GO_MIN_VERSION="1.19.0"

# Log file
LOG_FILE="install_log.txt"
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
mkdir -p logs
LOG_FILE="logs/install_${TIMESTAMP}.log"

# Function to log messages
log() {
    local level=$1
    shift
    local message=$@
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    case $level in
        "INFO")  echo -e "${GREEN}[*]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[!]${NC} $message" ;;
        "ERROR") echo -e "${RED}[x]${NC} $message" ;;
        *)       echo -e "${BLUE}[+]${NC} $message" ;;
    esac
}

# Function to check if running with sudo/root privileges
check_sudo() {
    if [ "$EUID" -eq 0 ]; then
        return 0
    fi
    return 1
}

# Function to request sudo privileges with explanation
request_sudo() {
    local reason=$1
    if ! check_sudo; then
        log "WARN" "Superuser privileges required for: $reason"
        log "INFO" "Please enter your password when prompted"
        if ! sudo -v; then
            log "ERROR" "Failed to obtain superuser privileges"
            echo -e "\nThe following operations require superuser privileges:"
            echo "- Installing system packages"
            echo "- Installing security tools"
            echo "- Configuring system-wide settings"
            echo "- Installing Go tools globally"
            echo -e "\nPlease run the script again with sudo or provide sudo password when prompted."
            exit 1
        fi
        # Keep sudo alive
        while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done 2>/dev/null &
    fi
}

# Function to check if elevated privileges are needed
check_privileges_requirement() {
    local needed=0
    
    # Check if system package installation is needed
    if ! check_command "nmap" || ! check_command "git" || ! check_command "python3"; then
        needed=1
    fi
    
    # Check if Go installation is needed
    if ! check_command "go"; then
        needed=1
    fi
    
    # Check if Docker installation is needed
    if ! check_command "docker"; then
        needed=1
    fi
    
    return $needed
}

# Function to check if a command exists
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check version
version_check() {
    local version=$1
    local required=$2
    if [ "$(printf '%s\n' "$required" "$version" | sort -V | head -n1)" = "$required" ]; then 
        return 0
    else
        return 1
    fi
}

# Function to detect package manager
detect_package_manager() {
    if command -v apt-get >/dev/null; then
        echo "apt"
    elif command -v dnf >/dev/null; then
        echo "dnf"
    elif command -v yum >/dev/null; then
        echo "yum"
    elif command -v pacman >/dev/null; then
        echo "pacman"
    elif command -v zypper >/dev/null; then
        echo "zypper"
    elif command -v brew >/dev/null; then
        echo "brew"
    elif command -v pkg >/dev/null; then
        echo "pkg"
    else
        echo "unknown"
    fi
}

# Function to get package names for different package managers
get_package_name() {
    local pkg_manager=$1
    local generic_name=$2
    
    case $pkg_manager in
        "apt")
            case $generic_name in
                "python3-dev") echo "python3-dev" ;;
                "libpcap") echo "libpcap-dev" ;;
                "chromium") echo "chromium-browser" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        "dnf"|"yum")
            case $generic_name in
                "python3-dev") echo "python3-devel" ;;
                "libpcap") echo "libpcap-devel" ;;
                "chromium-browser") echo "chromium" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        "pacman")
            case $generic_name in
                "python3-dev") echo "python-dev" ;;
                "libpcap") echo "libpcap" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        "brew")
            case $generic_name in
                "python3-dev") echo "python" ;;
                "libpcap") echo "libpcap" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        *)
            echo "$generic_name"
            ;;
    esac
}

# Function to install system packages
install_system_packages() {
    log "INFO" "Installing system packages..."
    
    # Detect OS and package manager
    OS=$(uname -s)
    PKG_MANAGER=$(detect_package_manager)
    
    log "INFO" "Detected OS: $OS"
    log "INFO" "Detected package manager: $PKG_MANAGER"
    
    # Request sudo privileges if needed
    if [ "$NO_SUDO" != true ] && [ "$PKG_MANAGER" != "brew" ]; then
        request_sudo "Installing system packages"
    fi
    
    # Define base packages needed
    declare -a BASE_PACKAGES=(
        "python3"
        "python3-pip"
        "python3-dev"
        "git"
        "curl"
        "wget"
        "nmap"
        "whois"
        "gcc"
        "make"
        "libpcap"
        "nodejs"
        "npm"
        "ruby"
        "ruby-dev"
    )
    
    # Install packages based on package manager
    case $PKG_MANAGER in
        "apt")
            sudo apt-get update
            for pkg in "${BASE_PACKAGES[@]}"; do
                pkg_name=$(get_package_name "$PKG_MANAGER" "$pkg")
                log "INFO" "Installing $pkg_name"
                sudo apt-get install -y "$pkg_name" 2>&1 | tee -a "$LOG_FILE"
            done
            ;;
        "dnf"|"yum")
            sudo $PKG_MANAGER update -y
            for pkg in "${BASE_PACKAGES[@]}"; do
                pkg_name=$(get_package_name "$PKG_MANAGER" "$pkg")
                log "INFO" "Installing $pkg_name"
                sudo $PKG_MANAGER install -y "$pkg_name" 2>&1 | tee -a "$LOG_FILE"
            done
            ;;
        "pacman")
            sudo pacman -Syu --noconfirm
            for pkg in "${BASE_PACKAGES[@]}"; do
                pkg_name=$(get_package_name "$PKG_MANAGER" "$pkg")
                log "INFO" "Installing $pkg_name"
                sudo pacman -S --noconfirm "$pkg_name" 2>&1 | tee -a "$LOG_FILE"
            done
            ;;
        "brew")
            brew update
            for pkg in "${BASE_PACKAGES[@]}"; do
                pkg_name=$(get_package_name "$PKG_MANAGER" "$pkg")
                log "INFO" "Installing $pkg_name"
                brew install "$pkg_name" 2>&1 | tee -a "$LOG_FILE"
            done
            ;;
        "pkg")
            sudo pkg update
            for pkg in "${BASE_PACKAGES[@]}"; do
                pkg_name=$(get_package_name "$PKG_MANAGER" "$pkg")
                log "INFO" "Installing $pkg_name"
                sudo pkg install -y "$pkg_name" 2>&1 | tee -a "$LOG_FILE"
            done
            ;;
        *)
            log "WARN" "Unknown package manager. You may need to install the following packages manually:"
            for pkg in "${BASE_PACKAGES[@]}"; do
                echo "- $pkg"
            done
            read -p "Continue with installation? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
    
    # Special handling for Windows (WSL or native)
    if [[ "$OS" == "Windows"* ]] || [[ -n "$WINDIR" ]]; then
        log "INFO" "Windows system detected, installing Windows-specific dependencies..."
        if command -v choco >/dev/null; then
            choco install -y python3 git curl wget nmap make nodejs npm ruby
        else
            log "WARN" "Chocolatey not found. Please install required packages manually:"
            echo "- Python 3"
            echo "- Git"
            echo "- Curl"
            echo "- Wget"
            echo "- Nmap"
            echo "- NodeJS"
            echo "- Ruby"
            read -p "Continue with installation? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
}

# Function to set up Python environment
setup_python_env() {
    log "INFO" "Setting up Python environment..."
    
    # Check Python version
    if ! check_command python3; then
        log "ERROR" "Python 3 is not installed"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
    if ! version_check "$PYTHON_VERSION" "$PYTHON_MIN_VERSION"; then
        log "ERROR" "Python version $PYTHON_VERSION is less than required version $PYTHON_MIN_VERSION"
        exit 1
    fi
    
    # Create virtual environment
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
    
    # Install Python dependencies
    log "INFO" "Installing Python dependencies..."
    pip install -r requirements.txt || {
        log "ERROR" "Failed to install Python dependencies"
        exit 1
    }
    
    # Install development dependencies if in dev mode
    if [ "$DEV_MODE" = true ]; then
        log "INFO" "Installing development dependencies..."
        pip install -r requirements-dev.txt || {
            log "ERROR" "Failed to install development dependencies"
            exit 1
        }
    fi
}

# Set up default configuration paths
setup_config_paths() {
    # Use XDG Base Directory if available, otherwise fallback to standard paths
    if [ -z "$XDG_CONFIG_HOME" ]; then
        XDG_CONFIG_HOME="$HOME/.config"
    fi
    if [ -z "$XDG_DATA_HOME" ]; then
        XDG_DATA_HOME="$HOME/.local/share"
    fi
    if [ -z "$XDG_CACHE_HOME" ]; then
        XDG_CACHE_HOME="$HOME/.cache"
    fi

    # Set up CodesHacks specific paths
    CODESHACKS_CONFIG_DIR="$XDG_CONFIG_HOME/codeshacks"
    CODESHACKS_DATA_DIR="$XDG_DATA_HOME/codeshacks"
    CODESHACKS_CACHE_DIR="$XDG_CACHE_HOME/codeshacks"
    CODESHACKS_TOOLS_DIR="$CODESHACKS_DATA_DIR/tools"
    CODESHACKS_LOGS_DIR="$CODESHACKS_DATA_DIR/logs"
    CODESHACKS_RESULTS_DIR="$CODESHACKS_DATA_DIR/results"

    # Export these paths for use in other functions
    export CODESHACKS_CONFIG_DIR CODESHACKS_DATA_DIR CODESHACKS_CACHE_DIR
    export CODESHACKS_TOOLS_DIR CODESHACKS_LOGS_DIR CODESHACKS_RESULTS_DIR
}

# Function to create tool directories
create_tool_directories() {
    log "INFO" "Creating tool directories..."
    
    # Ensure configuration paths are set up
    setup_config_paths
    
    # Create main tools directory structure
    mkdir -p "$CODESHACKS_TOOLS_DIR"/{recon,web,vuln,network,forensics,mobile}
    mkdir -p "$CODESHACKS_TOOLS_DIR"/recon/{subdomain,directory,assets}
    mkdir -p "$CODESHACKS_TOOLS_DIR"/web/{scanners,fuzzers,crawlers}
    mkdir -p "$CODESHACKS_TOOLS_DIR"/vuln/{scanners,exploits}
    mkdir -p "$CODESHACKS_TOOLS_DIR"/network/{scanners,sniffers}
    mkdir -p "$CODESHACKS_TOOLS_DIR"/mobile/{android,ios}
    
    # Create configuration directory
    mkdir -p "$CODESHACKS_CONFIG_DIR"/{tools,profiles,templates}
    
    # Create cache directory for temporary files
    mkdir -p "$CODESHACKS_CACHE_DIR"
    
    # Create logs and results directories
    mkdir -p "$CODESHACKS_LOGS_DIR"
    mkdir -p "$CODESHACKS_RESULTS_DIR"
    
    # Set tool directory paths
    TOOLS_DIR="$CODESHACKS_TOOLS_DIR"
    RECON_DIR="$TOOLS_DIR/recon"
    WEB_DIR="$TOOLS_DIR/web"
    VULN_DIR="$TOOLS_DIR/vuln"
    NETWORK_DIR="$TOOLS_DIR/network"
    FORENSICS_DIR="$TOOLS_DIR/forensics"
    MOBILE_DIR="$TOOLS_DIR/mobile"
    
    # Create symbolic links for backward compatibility
    if [ ! -L "$HOME/.codeshacks" ]; then
        ln -sf "$CODESHACKS_DATA_DIR" "$HOME/.codeshacks"
    fi
}

# Function to get tool information
get_tool_info() {
    local tool=$1
    local info_type=$2  # version, path, or capability
    local version_cmd=""
    local capability_cmd=""
    
    case $tool in
        "nmap")
            version_cmd="nmap --version | head -n1"
            capability_cmd="nmap -h | grep -E 'PORT SPECIFICATION|SCAN TECHNIQUES'"
            ;;
        "masscan")
            version_cmd="masscan --version | head -n1"
            capability_cmd="masscan --echo | grep -E 'rate|ports|range'"
            ;;
        "nikto")
            version_cmd="nikto -Version"
            capability_cmd="nikto -H | grep -E 'scan|plugins'"
            ;;
        "dirb")
            version_cmd="dirb 2>&1 | grep 'VERSION'"
            capability_cmd="dirb 2>&1 | grep -E 'OPTIONS|ARGUMENTS'"
            ;;
        "sqlmap")
            version_cmd="sqlmap --version"
            capability_cmd="sqlmap -h | grep -E 'Target|Request|Injection'"
            ;;
        "wfuzz")
            version_cmd="wfuzz -v | head -n1"
            capability_cmd="wfuzz -h | grep -E 'Parameters|Payload'"
            ;;
        "subfinder")
            version_cmd="subfinder -version"
            capability_cmd="subfinder -h | grep -E 'source|passive|active'"
            ;;
        "nuclei")
            version_cmd="nuclei -version"
            capability_cmd="nuclei -h | grep -E 'templates|severity|tags'"
            ;;
        "httpx")
            version_cmd="httpx -version"
            capability_cmd="httpx -h | grep -E 'probe|ports|title'"
            ;;
        *)
            version_cmd="$tool --version 2>/dev/null || $tool -version 2>/dev/null || $tool -V 2>/dev/null"
            capability_cmd="$tool -h 2>/dev/null || $tool --help 2>/dev/null"
            ;;
    esac
    
    case $info_type in
        "version")
            eval "$version_cmd" 2>/dev/null || echo "unknown"
            ;;
        "path")
            which "$tool" 2>/dev/null || echo ""
            ;;
        "capability")
            eval "$capability_cmd" 2>/dev/null || echo ""
            ;;
    esac
}

# Function to verify tool functionality
verify_tool() {
    local tool=$1
    local min_version=$2
    local result=0
    
    # Get tool information
    local tool_path=$(get_tool_info "$tool" "path")
    local tool_version=$(get_tool_info "$tool" "version")
    local tool_capabilities=$(get_tool_info "$tool" "capability")
    
    if [ -n "$tool_path" ]; then
        log "INFO" "Found $tool at: $tool_path"
        log "INFO" "Version: $tool_version"
        
        # Store tool information in global associative arrays
        TOOL_PATHS[$tool]="$tool_path"
        TOOL_VERSIONS[$tool]="$tool_version"
        
        # Check if tool is actually executable
        if ! command -v "$tool" >/dev/null 2>&1; then
            log "WARN" "Tool $tool found but may not be executable"
            result=1
        fi
        
        # Check tool capabilities
        if [ -n "$tool_capabilities" ]; then
            log "INFO" "Tool capabilities verified"
        else
            log "WARN" "Could not verify tool capabilities"
            result=1
        fi
    else
        log "INFO" "Tool $tool not found in system"
        result=1
    fi
    
    return $result
}

# Function to check pre-installed tools and verify their functionality
check_preinstalled_tools() {
    log "INFO" "Checking for pre-installed security tools..."
    
    # Initialize associative arrays for tool information
    declare -gA TOOL_PATHS
    declare -gA TOOL_VERSIONS
    declare -gA TOOL_REQUIREMENTS
    
    # Tool definitions with their requirements
    declare -A tools_info=(
        # Format: ["tool_name"]="min_version|required_capabilities|category"
        ["nmap"]="7.80|tcp,udp,script|network"
        ["masscan"]="1.3.2|rate,ports|network"
        ["nikto"]="2.1.6|scan,ssl|web"
        ["dirb"]="2.22|wordlist|web"
        ["whatweb"]="0.5.0|plugins|web"
        ["sqlmap"]="1.4|injection|web"
        ["wfuzz"]="3.0.0|fuzzing|web"
        ["hydra"]="9.0|brute|network"
        ["wireshark"]="3.0|capture|network"
        ["subfinder"]="2.5.0|passive,active|recon"
        ["nuclei"]="2.7.0|templates|vuln"
        ["httpx"]="1.2.0|probe|web"
        ["gobuster"]="3.0.0|dns,dir|web"
        ["ffuf"]="1.0.0|fuzz|web"
    )
    
    log "INFO" "Checking system and network tools..."
    for tool in "${!tools_info[@]}"; do
        IFS='|' read -r min_version capabilities category <<< "${tools_info[$tool]}"
        
        log "INFO" "Checking $tool (minimum version: $min_version)..."
        if verify_tool "$tool" "$min_version"; then
            log "INFO" "$tool is properly installed and functional"
            
            # Add to configuration
            echo "TOOL_${tool^^}_PATH=\"${TOOL_PATHS[$tool]}\"" >> "$CODESHACKS_CONFIG_DIR/tools.conf"
            echo "TOOL_${tool^^}_VERSION=\"${TOOL_VERSIONS[$tool]}\"" >> "$CODESHACKS_CONFIG_DIR/tools.conf"
            
            # Create symbolic link in appropriate category directory
            local category_dir="$CODESHACKS_TOOLS_DIR/$category"
            mkdir -p "$category_dir"
            ln -sf "${TOOL_PATHS[$tool]}" "$category_dir/"
        else
            log "INFO" "Adding $tool to installation queue"
            case $category in
                "network") MISSING_SYSTEM_TOOLS+=("$tool") ;;
                "web") MISSING_SYSTEM_TOOLS+=("$tool") ;;
                "recon") MISSING_GO_TOOLS+=("$tool") ;;
                "vuln") MISSING_GO_TOOLS+=("$tool") ;;
            esac
        fi
    done
    
    # Initialize associative arrays for tool paths
    declare -A TOOL_PATHS
    declare -A GO_TOOL_PATHS
    
    # Check system tools and store their paths
    log "INFO" "Checking system tools..."
    for tool in "${SYSTEM_TOOLS[@]}"; do
        local path=$(get_tool_path "$tool")
        if [ -n "$path" ]; then
            TOOL_PATHS[$tool]="$path"
            log "INFO" "Found existing $tool at: $path"
        else
            MISSING_SYSTEM_TOOLS+=("$tool")
            log "INFO" "Tool '$tool' needs to be installed"
        fi
    done
    
    # Check Go tools and store their paths
    log "INFO" "Checking Go tools..."
    for tool in "${GO_TOOLS[@]}"; do
        local path=$(get_go_path "$tool")
        if [ -n "$path" ]; then
            GO_TOOL_PATHS[$tool]="$path"
            log "INFO" "Found existing Go tool $tool at: $path"
        else
            MISSING_GO_TOOLS+=("$tool")
            log "INFO" "Go tool '$tool' needs to be installed"
        fi
    done
    
    # Initialize arrays for missing tools
    MISSING_SYSTEM_TOOLS=()
    MISSING_GO_TOOLS=()
    MISSING_PYTHON_TOOLS=()
    MISSING_NODE_TOOLS=()
    
    # Check system tools
    log "INFO" "Checking system tools..."
    for tool in "${SYSTEM_TOOLS[@]}"; do
        if ! check_command "$tool"; then
            MISSING_SYSTEM_TOOLS+=("$tool")
            log "INFO" "Tool '$tool' needs to be installed"
        else
            log "INFO" "Found existing installation of '$tool'"
        fi
    done
    
    # Check Go tools
    log "INFO" "Checking Go tools..."
    for tool in "${GO_TOOLS[@]}"; do
        if ! check_command "$tool"; then
            MISSING_GO_TOOLS+=("$tool")
            log "INFO" "Tool '$tool' needs to be installed"
        else
            log "INFO" "Found existing installation of '$tool'"
        fi
    done
    
    # Check Python tools
    log "INFO" "Checking Python tools..."
    for tool in "${PYTHON_TOOLS[@]}"; do
        if ! python3 -c "import $tool" 2>/dev/null; then
            MISSING_PYTHON_TOOLS+=("$tool")
            log "INFO" "Python package '$tool' needs to be installed"
        else
            log "INFO" "Found existing installation of '$tool'"
        fi
    done
    
    # Check Docker images
    log "INFO" "Checking Docker images..."
    declare -a DOCKER_IMAGES=(
        "ghcr.io/projectdiscovery/nuclei:latest"
        "owasp/zap2docker-stable"
        "portswigger/burp-rest-api"
        "opensecurity/mobile-security-framework-mobsf"
        "aquasec/trivy"
        "wpscanteam/wpscan"
        "citizenstig/nowasp"
    )
    
    MISSING_DOCKER_IMAGES=()
    for img in "${DOCKER_IMAGES[@]}"; do
        if ! docker image inspect "$img" >/dev/null 2>&1; then
            MISSING_DOCKER_IMAGES+=("$img")
            log "INFO" "Docker image '$img' needs to be pulled"
        else
            log "INFO" "Found existing Docker image '$img'"
        fi
    done
}

# Function to install security tools
install_security_tools() {
    log "INFO" "Installing security tools..."
    
    # Create tool directories first
    create_tool_directories
    
    # Check for pre-installed tools
    check_preinstalled_tools
    
    # Install Go if not present (required for many tools)
    if ! check_command go; then
        log "INFO" "Installing Go..."
        if [ "$NO_SUDO" != true ]; then
            request_sudo "Installing Go"
            wget https://golang.org/dl/go1.19.linux-amd64.tar.gz
            sudo tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            source ~/.bashrc
            rm go1.19.linux-amd64.tar.gz
        else
            log "ERROR" "Cannot install Go without superuser privileges"
            log "INFO" "Please install Go manually or run without --no-sudo"
            exit 1
        fi
    fi
    
    # Install missing Go tools
    if [ ${#MISSING_GO_TOOLS[@]} -gt 0 ]; then
        log "INFO" "Installing missing Go tools..."
        
        # Install Go if not present
        if ! check_command go; then
            log "INFO" "Installing Go..."
            wget https://golang.org/dl/go1.19.linux-amd64.tar.gz
            sudo tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            source ~/.bashrc
            rm go1.19.linux-amd64.tar.gz
        fi
        
        # ProjectDiscovery Tools
        if [[ " ${MISSING_GO_TOOLS[@]} " =~ " subfinder " ]] || \
           [[ " ${MISSING_GO_TOOLS[@]} " =~ " nuclei " ]] || \
           [[ " ${MISSING_GO_TOOLS[@]} " =~ " httpx " ]]; then
            log "INFO" "Installing ProjectDiscovery tools..."
            export GOBIN="$RECON_DIR/subdomain"
            [[ " ${MISSING_GO_TOOLS[@]} " =~ " subfinder " ]] && GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
            [[ " ${MISSING_GO_TOOLS[@]} " =~ " nuclei " ]] && GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            [[ " ${MISSING_GO_TOOLS[@]} " =~ " httpx " ]] && GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        fi
        
        # Directory Enumeration Tools
        if [[ " ${MISSING_GO_TOOLS[@]} " =~ " gobuster " ]] || \
           [[ " ${MISSING_GO_TOOLS[@]} " =~ " ffuf " ]]; then
            log "INFO" "Installing directory enumeration tools..."
            export GOBIN="$RECON_DIR/directory"
            [[ " ${MISSING_GO_TOOLS[@]} " =~ " gobuster " ]] && GO111MODULE=on go install -v github.com/OJ/gobuster/v3@latest
            [[ " ${MISSING_GO_TOOLS[@]} " =~ " ffuf " ]] && GO111MODULE=on go install -v github.com/ffuf/ffuf@latest
        fi
        
        # Asset Discovery Tools
        if [[ " ${MISSING_GO_TOOLS[@]} " =~ " waybackurls " ]] || \
           [[ " ${MISSING_GO_TOOLS[@]} " =~ " gau " ]]; then
            log "INFO" "Installing asset discovery tools..."
            export GOBIN="$RECON_DIR/assets"
            [[ " ${MISSING_GO_TOOLS[@]} " =~ " waybackurls " ]] && GO111MODULE=on go install -v github.com/tomnomnom/waybackurls@latest
            [[ " ${MISSING_GO_TOOLS[@]} " =~ " gau " ]] && GO111MODULE=on go install -v github.com/lc/gau/v2/cmd/gau@latest
        fi
    else
        log "INFO" "All Go tools are already installed"
    fi
    
    # Web Scanning Tools
    log "INFO" "Installing web scanning tools..."
    export GEM_HOME="$WEB_DIR/scanners"
    export PATH="$GEM_HOME/bin:$PATH"
    gem install wpscan
    export GOBIN="$NETWORK_DIR/scanners"
    GO111MODULE=on go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
    export GOBIN="$WEB_DIR/crawlers"
    GO111MODULE=on go install -v github.com/hakluke/hakrawler@latest
    
    # Vulnerability Scanning Tools
    log "INFO" "Installing vulnerability scanners..."
    export GOBIN="$VULN_DIR/scanners"
    GO111MODULE=on go install -v github.com/hahwul/dalfox/v2@latest
    python3 -m pip install --target="$NETWORK_DIR/scanners" dnsrecon
    python3 -m pip install --target="$VULN_DIR/scanners" droopescan
    python3 -m pip install --target="$NETWORK_DIR/scanners" sslyze
    
    # Install Node.js tools
    log "INFO" "Installing Node.js tools..."
    npm install -g wappalyzer-cli
    npm install -g retire
    npm install -g snyk
    
    # Install missing system tools using appropriate package manager
    if [ ${#MISSING_SYSTEM_TOOLS[@]} -gt 0 ]; then
        log "INFO" "Installing missing system tools..."
        case $PKG_MANAGER in
            "apt"|"dnf"|"yum"|"pacman"|"zypper")
                for tool in "${MISSING_SYSTEM_TOOLS[@]}"; do
                    pkg_name=$(get_package_name "$PKG_MANAGER" "$tool")
                    log "INFO" "Installing $pkg_name"
                    case $PKG_MANAGER in
                        "apt") sudo apt-get install -y "$pkg_name" ;;
                        "dnf"|"yum") sudo $PKG_MANAGER install -y "$pkg_name" ;;
                        "pacman") sudo pacman -S --noconfirm "$pkg_name" ;;
                        "zypper") sudo zypper install -y "$pkg_name" ;;
                    esac 2>&1 | tee -a "$LOG_FILE"
                done
                ;;
            "brew")
                for tool in "${MISSING_SYSTEM_TOOLS[@]}"; do
                    pkg_name=$(get_package_name "$PKG_MANAGER" "$tool")
                    log "INFO" "Installing $pkg_name"
                    brew install "$pkg_name" 2>&1 | tee -a "$LOG_FILE"
                done
                ;;
            *)
                log "WARN" "Package manager not supported for automatic tool installation."
                log "WARN" "Please install the following tools manually:"
                printf '%s\n' "${MISSING_SYSTEM_TOOLS[@]}"
                ;;
        esac
    else
        log "INFO" "All system tools are already installed"
    fi
    
    # Install Docker for containerized tools
    if ! check_command docker; then
        log "INFO" "Installing Docker..."
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker $USER
    fi
    
    # Pull useful Docker images
    log "INFO" "Pulling Docker images..."
    docker pull ghcr.io/projectdiscovery/nuclei:latest
    docker pull owasp/zap2docker-stable
    docker pull portswigger/burp-rest-api
    docker pull opensecurity/mobile-security-framework-mobsf
    docker pull aquasec/trivy
    docker pull wpscanteam/wpscan
    docker pull citizenstig/nowasp
    
    # Install missing Python-based tools
    if [ ${#MISSING_PYTHON_TOOLS[@]} -gt 0 ]; then
        log "INFO" "Installing missing Python-based security tools..."
        for tool in "${MISSING_PYTHON_TOOLS[@]}"; do
            log "INFO" "Installing $tool"
            pip3 install "$tool"
        done
    else
        log "INFO" "All Python tools are already installed"
    fi
    
    # Install missing Docker images
    if [ ${#MISSING_DOCKER_IMAGES[@]} -gt 0 ]; then
        log "INFO" "Pulling missing Docker images..."
        for img in "${MISSING_DOCKER_IMAGES[@]}"; do
            log "INFO" "Pulling $img"
            docker pull "$img"
        done
    else
        log "INFO" "All Docker images are already present"
    fi
    
    log "INFO" "Security tools installation completed!"
}

# Function to backup existing configuration
backup_config() {
    if [ -d ~/.codeshacks ]; then
        local backup_dir="$HOME/.codeshacks_backup_$(date +%Y%m%d_%H%M%S)"
        log "INFO" "Backing up existing configuration to $backup_dir"
        cp -r ~/.codeshacks "$backup_dir"
    fi
}

# Function to configure the tool
configure_tool() {
    log "INFO" "Configuring CodesHacks..."
    
    # Ensure configuration paths are set up
    setup_config_paths
    
    # Backup existing configuration if it exists
    backup_config
    
    # Copy config template if it exists
    if [ -f "config.template.json" ]; then
        cp config.template.json "$CODESHACKS_CONFIG_DIR/config.json"
    fi
    
    # Create tool-specific configuration files with tool paths
    {
        cat > "$CODESHACKS_CONFIG_DIR/paths.conf" << EOF
# CodesHacks Path Configuration
CODESHACKS_CONFIG_DIR="$CODESHACKS_CONFIG_DIR"
CODESHACKS_DATA_DIR="$CODESHACKS_DATA_DIR"
CODESHACKS_CACHE_DIR="$CODESHACKS_CACHE_DIR"
CODESHACKS_TOOLS_DIR="$CODESHACKS_TOOLS_DIR"
CODESHACKS_LOGS_DIR="$CODESHACKS_LOGS_DIR"
CODESHACKS_RESULTS_DIR="$CODESHACKS_RESULTS_DIR"

# Pre-installed Tool Paths
EOF

        # Add system tool paths
        for tool in "${!TOOL_PATHS[@]}"; do
            echo "TOOL_PATH_${tool^^}=\"${TOOL_PATHS[$tool]}\"" >> "$CODESHACKS_CONFIG_DIR/paths.conf"
        done

        # Add Go tool paths
        echo -e "\n# Go Tool Paths" >> "$CODESHACKS_CONFIG_DIR/paths.conf"
        for tool in "${!GO_TOOL_PATHS[@]}"; do
            echo "GO_TOOL_PATH_${tool^^}=\"${GO_TOOL_PATHS[$tool]}\"" >> "$CODESHACKS_CONFIG_DIR/paths.conf"
        done
    }
    
    # Create default profiles directory with example
    mkdir -p "$CODESHACKS_CONFIG_DIR/profiles"
    {
        cat > "$CODESHACKS_CONFIG_DIR/profiles/default.conf" << EOF
# Default scanning profile
scan_type=full
threads=10
timeout=30
user_agent="CodesHacks Scanner v1.0"
follow_redirects=true
max_depth=3
EOF
    }
    
    # Add tool paths to environment
    {
        echo "# CodesHacks Environment Configuration"
        echo "# Added by CodesHacks installer on $(date)"
        echo ""
        echo "# XDG Base Directories"
        echo "export XDG_CONFIG_HOME=\"\${XDG_CONFIG_HOME:-\$HOME/.config}\""
        echo "export XDG_DATA_HOME=\"\${XDG_DATA_HOME:-\$HOME/.local/share}\""
        echo "export XDG_CACHE_HOME=\"\${XDG_CACHE_HOME:-\$HOME/.cache}\""
        echo ""
        echo "# CodesHacks Directories"
        echo "export CODESHACKS_CONFIG_DIR=\"\$XDG_CONFIG_HOME/codeshacks\""
        echo "export CODESHACKS_DATA_DIR=\"\$XDG_DATA_HOME/codeshacks\""
        echo "export CODESHACKS_CACHE_DIR=\"\$XDG_CACHE_HOME/codeshacks\""
        echo "export CODESHACKS_TOOLS_DIR=\"\$CODESHACKS_DATA_DIR/tools\""
        echo "export CODESHACKS_LOGS_DIR=\"\$CODESHACKS_DATA_DIR/logs\""
        echo "export CODESHACKS_RESULTS_DIR=\"\$CODESHACKS_DATA_DIR/results\""
        echo ""
        echo "# Tool Paths"
        echo "export PATH=\"\$CODESHACKS_TOOLS_DIR/recon/subdomain:\$PATH\""
        echo "export PATH=\"\$CODESHACKS_TOOLS_DIR/recon/directory:\$PATH\""
        echo "export PATH=\"\$CODESHACKS_TOOLS_DIR/recon/assets:\$PATH\""
        echo "export PATH=\"\$CODESHACKS_TOOLS_DIR/web/scanners/bin:\$PATH\""
        echo "export PATH=\"\$CODESHACKS_TOOLS_DIR/web/crawlers:\$PATH\""
        echo "export PATH=\"\$CODESHACKS_TOOLS_DIR/vuln/scanners:\$PATH\""
        echo "export PATH=\"\$CODESHACKS_TOOLS_DIR/network/scanners:\$PATH\""
        echo ""
        echo "# Load CodesHacks completion if available"
        echo "[ -f \"\$CODESHACKS_CONFIG_DIR/completion.sh\" ] && source \"\$CODESHACKS_CONFIG_DIR/completion.sh\""
    } >> ~/.bashrc
    
    # Create symlinks for commonly used tools
    mkdir -p ~/.codeshacks/bin
    ln -sf ~/.codeshacks/tools/*/*/*/* ~/.codeshacks/bin/ 2>/dev/null
    echo "export PATH=\"\$HOME/.codeshacks/bin:\$PATH\"" >> ~/.bashrc
}

# Function to verify tool installations
verify_installations() {
    log "INFO" "Verifying tool installations..."
    
    # Array of critical tools to verify
    declare -A tools=(
        ["subfinder"]="$RECON_DIR/subdomain/subfinder"
        ["nuclei"]="$RECON_DIR/subdomain/nuclei"
        ["httpx"]="$RECON_DIR/subdomain/httpx"
        ["katana"]="$WEB_DIR/crawlers/katana"
        ["gobuster"]="$RECON_DIR/directory/gobuster"
        ["ffuf"]="$RECON_DIR/directory/ffuf"
        ["waybackurls"]="$RECON_DIR/assets/waybackurls"
        ["dalfox"]="$VULN_DIR/scanners/dalfox"
    )
    
    local failed=0
    
    for tool in "${!tools[@]}"; do
        if [ ! -f "${tools[$tool]}" ] && [ ! -f "${tools[$tool]}.exe" ]; then
            log "ERROR" "Tool $tool not found in expected location: ${tools[$tool]}"
            failed=1
        else
            log "INFO" "Verified $tool installation"
        fi
    done
    
    # Verify Python packages
    local python_packages=("dnspython" "fierce" "urlscan" "xsrfprobe")
    for pkg in "${python_packages[@]}"; do
        if ! pip show "$pkg" >/dev/null 2>&1; then
            log "ERROR" "Python package $pkg not installed properly"
            failed=1
        else
            log "INFO" "Verified Python package $pkg"
        fi
    done
    
    # Verify Docker images
    local docker_images=("ghcr.io/projectdiscovery/nuclei:latest" "owasp/zap2docker-stable")
    for img in "${docker_images[@]}"; do
        if ! docker image inspect "$img" >/dev/null 2>&1; then
            log "ERROR" "Docker image $img not pulled properly"
            failed=1
        else
            log "INFO" "Verified Docker image $img"
        fi
    done
    
    if [ $failed -eq 1 ]; then
        log "ERROR" "Some tools were not installed correctly"
        return 1
    fi
    
    log "INFO" "All tools verified successfully"
    return 0
}

# Function to cleanup unnecessary files
cleanup_workspace() {
    log "INFO" "Cleaning up workspace..."
    
    # List of files and directories to check for removal
    declare -a CLEANUP_PATHS=(
        "codeshacks.py.bak"      # Backup files
        "help_text.py"           # Old help text file
        "__pycache__"            # Python cache directories
        "*.pyc"                  # Compiled Python files
        ".pytest_cache"          # Pytest cache
        "*.log"                  # Log files except current log
        "temp_*"                # Temporary files
        "*.bak"                 # Backup files
        "*.swp"                 # Vim swap files
        ".coverage"             # Coverage reports
        "htmlcov"               # HTML coverage reports
        "build"                 # Build directories
        "dist"                  # Distribution directories
        "*.egg-info"           # Python egg metadata
    )
    
    # Counter for freed space
    local space_before=$(du -sb . 2>/dev/null | cut -f1)
    
    for pattern in "${CLEANUP_PATHS[@]}"; do
        # Find and remove matching files, excluding certain paths
        find . -name "$pattern" \
            ! -path "./venv/*" \
            ! -path "./.git/*" \
            ! -path "./tests/*" \
            ! -path "./results/*" \
            ! -path "./logs/install_${TIMESTAMP}.log" \
            -type f -o -type d 2>/dev/null | while read -r item; do
            if [ -e "$item" ]; then
                log "INFO" "Removing: $item"
                if [ -d "$item" ]; then
                    rm -rf "$item"
                else
                    rm -f "$item"
                fi
            fi
        done
    done
    
    # Calculate freed space
    local space_after=$(du -sb . 2>/dev/null | cut -f1)
    local space_freed=$((space_before - space_after))
    
    if [ $space_freed -gt 0 ]; then
        local space_freed_mb=$(echo "scale=2; $space_freed/1048576" | bc)
        log "INFO" "Freed up ${space_freed_mb}MB of disk space"
    fi
    
    # Optimize Python compiled files
    if command -v python3 >/dev/null; then
        log "INFO" "Optimizing Python bytecode..."
        python3 -OO -m compileall -q -j 0 .
    fi
}

# Function to upgrade system packages
upgrade_system_packages() {
    log "INFO" "Upgrading system packages..."
    
    case $PKG_MANAGER in
        "apt")
            sudo apt-get update && sudo apt-get upgrade -y
            ;;
        "dnf"|"yum")
            sudo $PKG_MANAGER update -y
            ;;
        "pacman")
            sudo pacman -Syu --noconfirm
            ;;
        "brew")
            brew update && brew upgrade
            ;;
        *)
            log "WARN" "Unknown package manager: $PKG_MANAGER"
            return 1
            ;;
    esac
}

# Function to upgrade Python packages
upgrade_python_packages() {
    log "INFO" "Upgrading Python packages..."
    
    # Activate virtual environment if it exists
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    fi
    
    # Upgrade pip itself
    python3 -m pip install --upgrade pip
    
    # Upgrade all packages in requirements.txt
    if [ -f "requirements.txt" ]; then
        pip install --upgrade -r requirements.txt
    fi
    
    # Upgrade development packages if in dev mode
    if [ "$DEV_MODE" = true ] && [ -f "requirements-dev.txt" ]; then
        pip install --upgrade -r requirements-dev.txt
    fi
}

# Function to upgrade Go tools
upgrade_go_tools() {
    log "INFO" "Upgrading Go tools..."
    
    # Update Go tools from tools.conf
    if [ -f "$CODESHACKS_CONFIG_DIR/tools.conf" ]; then
        while IFS='=' read -r name path; do
            if [[ $name == TOOL_*_PATH ]] && [[ $path == *"/go/bin/"* ]]; then
                tool_name=$(echo "$name" | sed 's/TOOL_\(.*\)_PATH/\1/' | tr '[:upper:]' '[:lower:]')
                log "INFO" "Upgrading $tool_name..."
                GO111MODULE=on go install -v "$path"@latest
            fi
        done < "$CODESHACKS_CONFIG_DIR/tools.conf"
    fi
}

# Function to upgrade Node.js tools
upgrade_node_tools() {
    log "INFO" "Upgrading Node.js tools..."
    
    if command -v npm >/dev/null; then
        # Upgrade npm itself
        npm install -g npm@latest
        
        # Upgrade global packages
        npm update -g
    fi
}

# Function to upgrade Docker images
upgrade_docker_images() {
    log "INFO" "Upgrading Docker images..."
    
    if command -v docker >/dev/null; then
        docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>" | while read -r image; do
            log "INFO" "Pulling latest version of $image"
            docker pull "$image"
        done
        
        # Remove unused images
        docker image prune -f
    fi
}

# Function to upgrade all tools and dependencies
upgrade_all() {
    log "INFO" "Starting comprehensive upgrade process..."
    
    # Create upgrade log
    UPGRADE_LOG="$CODESHACKS_LOGS_DIR/upgrade_${TIMESTAMP}.log"
    
    # Backup current configuration
    backup_config
    
    # Upgrade system packages first
    upgrade_system_packages 2>&1 | tee -a "$UPGRADE_LOG"
    
    # Upgrade Python environment and packages
    upgrade_python_packages 2>&1 | tee -a "$UPGRADE_LOG"
    
    # Upgrade Go tools
    upgrade_go_tools 2>&1 | tee -a "$UPGRADE_LOG"
    
    # Upgrade Node.js tools
    upgrade_node_tools 2>&1 | tee -a "$UPGRADE_LOG"
    
    # Upgrade Docker images
    upgrade_docker_images 2>&1 | tee -a "$UPGRADE_LOG"
    
    # Verify all upgrades
    if ! verify_installations; then
        log "ERROR" "Some upgrades may have failed. Please check $UPGRADE_LOG"
        return 1
    fi
    
    log "INFO" "Upgrade process completed successfully!"
    log "INFO" "Upgrade log saved to: $UPGRADE_LOG"
}

# Function to run tests
run_tests() {
    log "INFO" "Running tests..."
    if [ "$DEV_MODE" = true ]; then
        pytest tests/ || {
            log "ERROR" "Tests failed"
            exit 1
        }
    fi
}

# Main installation function
main() {
    log "INFO" "Starting CodesHacks installation..."
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dev)
                DEV_MODE=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --no-sudo)
                NO_SUDO=true
                shift
                ;;
            --upgrade)
                UPGRADE_MODE=true
                shift
                ;;
            --upgrade-only)
                UPGRADE_ONLY=true
                shift
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --dev          Install development dependencies"
                echo "  --skip-tests   Skip running tests"
                echo "  --no-sudo      Skip operations requiring superuser privileges"
                echo "  --upgrade      Install and upgrade all components"
                echo "  --upgrade-only Only upgrade existing installations"
                echo ""
                echo "Examples:"
                echo "  $0                   # Normal installation"
                echo "  $0 --dev             # Development installation"
                echo "  $0 --upgrade         # Install and upgrade"
                echo "  $0 --upgrade-only    # Only upgrade existing components"
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Check if running directly as root (not recommended)
    if [ "$EUID" -eq 0 ]; then
        log "WARN" "Running as root is not recommended. Consider running as normal user with sudo privileges."
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check if privileges are needed
    if check_privileges_requirement; then
        if [ "$NO_SUDO" = true ]; then
            log "ERROR" "This installation requires superuser privileges, but --no-sudo was specified"
            log "INFO" "You can:"
            echo "1. Run without --no-sudo to allow sudo operations"
            echo "2. Install required system packages manually first"
            echo "3. Run with --help to see all options"
            exit 1
        fi
        
        # Display privilege requirements
        echo -e "\n${YELLOW}This installation requires superuser privileges for:${NC}"
        echo "- Installing system packages"
        echo "- Setting up security tools"
        echo "- Configuring system paths"
        echo "- Installing global dependencies"
        echo -e "\n${BLUE}The script will prompt for sudo password when needed.${NC}"
        read -p "Continue with installation? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Handle different execution modes
    if [ "$UPGRADE_ONLY" = true ]; then
        # Only perform upgrades
        log "INFO" "Running in upgrade-only mode..."
        if ! upgrade_all; then
            log "ERROR" "Upgrade process failed"
            exit 1
        fi
    else
        # Normal installation flow
        install_system_packages
        setup_python_env
        install_security_tools
        configure_tool
        
        # Perform upgrades if requested
        if [ "$UPGRADE_MODE" = true ]; then
            if ! upgrade_all; then
                log "ERROR" "Upgrade process failed"
                exit 1
            fi
        fi
        
        # Clean up unnecessary files
        cleanup_workspace
        
        # Verify installations
        if ! verify_installations; then
            log "ERROR" "Installation verification failed"
            exit 1
        fi
    fi
    
    # Run tests unless skipped
    if [ "$SKIP_TESTS" != true ]; then
        run_tests
    fi
    
    log "INFO" "Installation completed successfully!"
    log "INFO" "Log file: $LOG_FILE"
    
    # Print usage instructions
    echo -e "\n${GREEN}CodesHacks has been installed successfully!${NC}"
    echo -e "\nTo get started:"
    echo -e "1. Activate the virtual environment:"
    echo -e "   ${BLUE}source venv/bin/activate${NC}"
    echo -e "2. Run CodesHacks:"
    echo -e "   ${BLUE}python3 codeshacks.py --help${NC}"
    echo -e "\nFor documentation, visit:"
    echo -e "${BLUE}https://github.com/RAJSHRIVASTAV397/CodesHacks${NC}"
}

# Run main function
main "$@"