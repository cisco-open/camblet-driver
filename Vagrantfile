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
    vbox.cpus   = 2
  end
 
  config.vm.define "ubnt", primary: true do |ubnt|
    ubnt.vm.box = "ubuntu/jammy64"
    ubnt.vm.network "forwarded_port", id: "opossum", guest: 9101, host: 9101
    ubnt.vm.provision "shell", privileged: false, inline: <<-SHELL
    set KERNEL="$(uname -r)"
    sudo apt-get update -q
    sudo apt-get install -q -y curl \
        "linux-headers-${KERNEL}" \
        build-essential \
        kmod \
        docker.io \
        socat \
        zsh \
        clang \
        libbpf-dev \
        gcc-multilib
    sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    sudo usermod -s /bin/zsh ${USER}
    # curl -sfL https://get.k3s.io | sh -
    # sudo chmod 0644 /etc/rancher/k3s/k3s.yaml
  SHELL
  end

  config.vm.define "arch", autostart: false do |arch|
    arch.vm.box = "archlinux/archlinux"
    arch.vm.network "forwarded_port", id: "opossum", guest: 9101, host: 9102 
    arch.vm.provision "shell", privileged: false, inline: <<-SHELL
    sudo pacman -Syu --noconfirm
    sudo pacman -S --noconfirm \
                  base-devel \
                  linux-headers \
                  dnsutils \
                  docker \
                  socat \
                  git \
                  zsh \
                  bpf \
                  clang
    sudo systemctl enable docker
    sudo systemctl start docker
    sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    sudo usermod -s /bin/zsh ${USER}
    # curl -sfL https://get.k3s.io | sh -
    # sudo chmod 0644 /etc/rancher/k3s/k3s.yaml
    sudo reboot
  SHELL
  end
end
