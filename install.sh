#!/bin/bash
echo "Installing CodesHacks Reconnaissance Tool"

# Update package lists
sudo apt-get update

# Install Python and pip
sudo apt-get install -y python3 python3-pip

# Install Python dependencies from requirements.txt
pip3 install -r requirements.txt

# Install Subfinder
echo "Installing Subfinder..."
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip
unzip subfinder_2.6.3_linux_amd64.zip
chmod +x subfinder
sudo mv subfinder /usr/local/bin/
rm subfinder_2.6.3_linux_amd64.zip

# Install nmap for active scanning
sudo apt-get install -y nmap

# Install wappalyzer CLI
npm install -g wappalyzer-cli

echo "Installation complete!"
echo "Run: python3 codeshacks.py --help to get started"