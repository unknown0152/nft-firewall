# Testing NFT Firewall with Vagrant

To test the NFT Firewall in a clean environment, you can use Vagrant. This will spin up a Debian 12 (Bookworm) virtual machine and automatically run the installer.

## Prerequisites

- [Vagrant](https://www.vagrantup.com/downloads) installed.
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (or another provider like libvirt/VMware) installed.

## Quick Start

1.  **Spin up the VM:**
    ```bash
    vagrant up
    ```
    This command will:
    - Download the Debian 12 box if you don't have it.
    - Create a new VM.
    - Sync the current project directory to `/home/vagrant/nft-firewall` in the VM.
    - Run the `setup.py install` with safe defaults (pre-configured in `config/firewall.ini`).

2.  **Access the VM:**
    ```bash
    vagrant ssh
    ```

3.  **Check Firewall Status:**
    Once inside the VM, you can check if everything is running:
    ```bash
    fw status
    ```

4.  **Run Chaos Tests:**
    You can run the chaos engineering suite to see the firewall in action:
    ```bash
    sudo bash /opt/nft-firewall/tests/chaos_test.sh
    ```

5.  **Clean up:**
    When you are done testing, you can destroy the VM:
    ```bash
    vagrant destroy
    ```

## Configuration for Vagrant

The `Vagrantfile` automatically creates a `config/firewall.ini` if it doesn't exist, using defaults that work within the Vagrant environment (e.g., `eth0` as the physical interface).

If you want to test specific configurations, you can edit `config/firewall.ini` on your host machine before running `vagrant up` (or `vagrant provision` if the VM is already running).
