#!/bin/bash

# Shell script to install security scanning tools for AI Security Tester
echo "Installing security scanning tools for AI Security Tester..."

# Check if running on macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    echo "Detected macOS"
    
    # Install Homebrew if not present
    if ! command -v brew &> /dev/null; then
        echo "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install tools with Homebrew
    echo "Installing Nmap..."
    brew install nmap
    
    echo "Installing Go..."
    brew install go
    
    echo "Installing Nikto..."
    brew install nikto
    
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    echo "Detected Linux"
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian
        echo "Installing tools with apt..."
        sudo apt-get update
        sudo apt-get install -y nmap golang-go nikto
        
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL
        echo "Installing tools with yum..."
        sudo yum install -y nmap golang nikto
        
    elif command -v dnf &> /dev/null; then
        # Fedora
        echo "Installing tools with dnf..."
        sudo dnf install -y nmap golang nikto
        
    else
        echo "Unsupported Linux distribution. Please install Nmap, Go, and Nikto manually."
        exit 1
    fi
else
    echo "Unsupported operating system. Please install tools manually."
    exit 1
fi

# Set up Go environment
echo "Setting up Go environment..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:$HOME/go/bin

# Add to shell profile
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo 'export GOPATH=$HOME/go' >> ~/.zshrc
    echo 'export PATH=$PATH:$GOPATH/bin:$HOME/go/bin' >> ~/.zshrc
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin:$HOME/go/bin' >> ~/.bashrc
fi

# Install Go tools
echo "Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Nuclei templates
echo "Updating Nuclei templates..."
nuclei -update-templates

# Test installations
echo "Testing tool installations..."

if command -v nmap &> /dev/null; then
    echo "✓ Nmap installed: $(nmap --version | head -n1)"
else
    echo "✗ Nmap not found in PATH"
fi

if command -v subfinder &> /dev/null; then
    echo "✓ Subfinder installed: $(subfinder -version)"
else
    echo "✗ Subfinder not found in PATH"
fi

if command -v nuclei &> /dev/null; then
    echo "✓ Nuclei installed: $(nuclei -version)"
else
    echo "✗ Nuclei not found in PATH"
fi

if command -v nikto &> /dev/null; then
    echo "✓ Nikto installed"
else
    echo "✗ Nikto not found in PATH"
fi

echo "Setup script completed!"
echo "Please restart your terminal or run 'source ~/.bashrc' (Linux) or 'source ~/.zshrc' (macOS) to use the new tools."
