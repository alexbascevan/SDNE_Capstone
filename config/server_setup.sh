# Copy 1 line at a time  
# Make sure network adapter is in before running
# Your network adapter may not be "<adapter name>", after running line 17, type "ip a" and use the adapter name below, ex."wlan0"
# Input your info at the end for github

# Enable SSH
sudo systemctl enable ssh

# Update and upgrade system packages
sudo apt update -y && sudo apt upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y

# Install required packages
sudo apt install -y dhcpcd5 iw build-essential libssl-dev libpcap-dev pkg-config zlib1g-dev autoconf git-all gh python3 python3-boto3 python3-flask-cors python3-scapy python3-numpy python3-flask python3-requests net-tools wireless-tools zsh fastfetch locate python3-pip sqlite3 

# Install BrosTrend Wi-Fi adapter driver
sh -c 'wget linux.brostrend.com/install -O /tmp/install && sh /tmp/install'

# Bring up the network interface and assign static IP
sudo ip link set <adapter name> up  
sudo ip addr add 192.168.1.100/24 dev <adapter name>
sudo ip link set <adapter name> down

# Configure static IP in dhcpcd.conf
echo -e "\n# Static IP configuration for interface <adapter name>\ninterface <adapter name>\nstatic ip_address=192.168.1.100/24\nstatic routers=192.168.1.1\nstatic domain_name_servers=8.8.8.8 8.8.4.4" | sudo tee -a /etc/dhcpcd.conf > /dev/null
sudo systemctl restart dhcpcd

# Create systemd service to set Wi-Fi adapter to monitor mode
echo -e "[Unit]\nDescription=Set Wi-Fi adapter to monitor mode\nAfter=network.target\n\n[Service]\nType=oneshot\nExecStartPre=/bin/sleep 5\nExecStartPre=/sbin/ip link set <adapter name> down\nExecStartPre=/bin/sleep 2\nExecStartPre=/usr/sbin/iw dev <adapter name> set type monitor\nExecStart=/sbin/ip link set <adapter name> up\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target" | sudo tee /etc/systemd/system/wifi-monitor.service > /dev/null

# Reload systemd and enable the wifi-monitor service
sudo systemctl daemon-reload
sudo systemctl enable wifi-monitor.service
sudo systemctl start wifi-monitor.service

# Confirm Monitor Mode is active
iw dev <adapter name> info

# Install Oh My Zsh and plugins
sh -c "$(curl -fsSL https://install.ohmyz.sh/)"
git clone https://github.com/zsh-users/zsh-autosuggestions.git $ZSH_CUSTOM/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $ZSH_CUSTOM/plugins/zsh-syntax-highlighting
git clone https://github.com/romkatv/powerlevel10k.git $ZSH_CUSTOM/themes/powerlevel10k

# Configure and reload .zshrc
echo -e "# Enable fastfetch\nfastfetch\n\n# Enable Powerlevel10k instant prompt\n# Initialization code that may require console input\nif [[ -r \"\${XDG_CACHE_HOME:-\$HOME/.cache}/p10k-instant-prompt-\${(%):-%n}.zsh\" ]]; then\n  source \"\${XDG_CACHE_HOME:-\$HOME/.cache}/p10k-instant-prompt-\${(%):-%n}.zsh\"\nfi\n\n# Zsh configuration\nexport ZSH=\"\$HOME/.oh-my-zsh\"\nZSH_THEME=\"powerlevel10k/powerlevel10k\"\nplugins=(git zsh-autosuggestions zsh-syntax-highlighting)\nsource \$ZSH/oh-my-zsh.sh" | sudo tee /home/$USER/.zshrc > /dev/null
source ~/.zshrc

# Disable motd-news service
sudo systemctl stop motd-news.service
sudo systemctl disable motd-news.service
sudo chmod -x /etc/update-motd.d/*

# Configure GitHub CLI 
gh auth login   # Generate personal access token
git config --global init.defaultBranch main
git config --global user.email "you@example.com"
git config --global user.name "Your Name"

# Setup Capstone repository
mkdir Capstone
cd Capstone
git init
git pull https://github.com/alexbascevan/SDNE_Capstone.git

# Update file databases
sudo updatedb

# Reboot System 
sudo reboot now

# Confirm Monitor Mode is active after reboot

iw dev <adapter name> info


# If having errors with script setting wifi adapter to monitor mode, run these manually. Be sure to update the adapter name to your specific adapter.
# Bring the interface down
sudo ip link set <adapter name> down

# Set the interface to monitor mode
sudo iw dev <adapter name> set type monitor

# Bring the interface up
sudo ip link set <adapter name> up

sudo mv runScanner.sh /usr/local/bin/runScanner
