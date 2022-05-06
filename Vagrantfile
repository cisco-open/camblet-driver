# -*- mode: ruby -*-
# vi: set ft=ruby :

vbox_name = "wasm3"

unless Vagrant.has_plugin?("vagrant-vbguest")
  vbguest_installed = false
else
  vbguest_installed = true
end

ENV["LC_ALL"] = "en_US.UTF-8"
Vagrant.require_version ">= 2.2.0"

Vagrant.configure("2") do |config|
  config.vm.box      = "ubuntu/jammy64"
  config.vm.hostname = vbox_name
  config.ssh.shell   = "bash -c 'BASH_ENV=/etc/profile exec bash'"

  config.vagrant.plugins = ["vagrant-vbguest"]

  if vbguest_installed
    config.vbguest.auto_update = false
    config.vbguest.no_install  = true
  end

  config.vm.provider "virtualbox" do |vbox|
    vbox.gui    = false
    vbox.memory = "4096"
    vbox.cpus   = 4
    vbox.name   = vbox_name
  end

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    set KERNEL="$(uname -r)"
    sudo apt-get update -q
    sudo apt-get install -q -y curl \
        "linux-headers-${KERNEL}" \
        build-essential \
        kmod \
        docker.io \
        socat \
        zsh
    sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    sudo usermod -s /bin/zsh ${USER}
    curl -sfL https://get.k3s.io | sh -
    sudo chmod 0644 /etc/rancher/k3s/k3s.yaml
  SHELL
end
