# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"

  # VM Resources
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
    vb.cpus = 1
  end

  # Sync the current directory to the VM
  # We sync to /home/vagrant/nft-firewall
  config.vm.synced_folder ".", "/home/vagrant/nft-firewall"

  # Provisioning
  config.vm.provision "shell", inline: <<-SHELL
    set -e
    export DEBIAN_FRONTEND=noninteractive

    echo "[+] Installing dependencies..."
    apt-get update -qq
    apt-get install -y -qq git python3 python3-pip nftables wireguard-tools curl

    # Navigate to project
    cd /home/vagrant/nft-firewall

    # Create a default firewall.ini if it doesn't exist to avoid interactive prompts
    if [ ! -f config/firewall.ini ]; then
      echo "[+] Pre-configuring firewall.ini for Vagrant environment..."
      mkdir -p config
      cat > config/firewall.ini <<EOF
[network]
phy_if = eth0
vpn_interface = wg0
lan_net = 10.0.2.0/24
vpn_server_ip = 1.2.3.4
vpn_server_port = 51820
ssh_port = 22
lan_full_access = false
lan_allow_ports = 22, 32400

[install]
profile = cosmos-vpn-secure
EOF
    fi

    echo "[+] Running NFT Firewall installation..."
    # Run setup.py. We use sudo as required.
    # Since we provided firewall.ini, it should skip Step 0 interactive wizard.
    sudo python3 setup.py install

    echo ""
    echo "================================================================="
    echo "  NFT Firewall installed successfully in Vagrant!"
    echo "  Run 'vagrant ssh' to enter the VM."
    echo "  Inside the VM, use 'fw' to manage the firewall."
    echo "================================================================="
  SHELL
end
