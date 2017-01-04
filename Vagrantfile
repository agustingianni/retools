Vagrant.configure("2") do |config|
  # Define the characteristics of the vm's we are using.
  config.vm.provider "virtualbox" do |virtualbox|
    virtualbox.memory = 4096
    virtualbox.cpus = 1
  end

  # Run this script on every vm.
  config.vm.provision :shell, path: "bootstrap.sh"

  # Create an ubuntu vm and make it the default.
  config.vm.define "ubuntu", primary: true do |ubuntu|
    ubuntu.vm.box = "ubuntu/xenial64"
  end

  # Create a debian vm.
  config.vm.define "debian" do |debian|
    debian.vm.box = "debian/jessie64"
  end
end