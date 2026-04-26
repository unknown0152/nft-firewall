# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"

  # VM Resources - using libvirt for native Linux speed
  config.vm.provider "libvirt" do |lv|
    lv.memory = 1024
    lv.cpus = 1
    lv.cpu_mode = "host-passthrough"
    lv.nic_model_type = "virtio"
  end

  # Sync the current directory to the VM
  config.vm.synced_folder ".", "/home/vagrant/nft-firewall", type: "rsync"

  # Standard NAT networking (most reliable)
  config.vm.network "private_network", type: "dhcp", libvirt__forward_mode: "nat"

  # Provisioning
  config.vm.provision "shell", inline: <<-SHELL
    set -e
    export DEBIAN_FRONTEND=noninteractive

    echo "[+] Installing dependencies..."
    apt-get update -qq
    apt-get install -y -qq git python3 python3-pip nftables wireguard-tools curl openresolv unzip

    # Navigate to project
    cd /home/vagrant/nft-firewall

    # Create a default firewall.ini if it doesn't exist
    if [ ! -f config/firewall.ini ]; then
      echo "[+] Pre-configuring firewall.ini for Vagrant..."
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
    sudo python3 setup.py install

    echo ""
    echo "================================================================="
    echo "  NFT Firewall installed successfully in Vagrant!"
    echo "  Run 'vagrant ssh' to enter the VM."
    echo "  Inside the VM, use 'fw' to manage the firewall."
    echo "================================================================="
  SHELL
end
