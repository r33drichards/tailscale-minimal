{ config, pkgs, ... }:

{
  system.stateVersion = "23.05";

  sshconfMod = {
    users.users.noisebridge = {
      isNormalUser = true;
      # extraGroups = [ "wheel" ]; # Enable ‘sudo’ for the user.
    };
    # allow sudo without password for wheel
    # security.sudo.wheelNeedsPassword = false;

    # port 22
    networking.firewall.allowedTCPPorts = [ 22 ];

    services.openssh = {
      enable = true;
      # require public key authentication for better security
      settings.PasswordAuthentication = false;
      settings.KbdInteractiveAuthentication = false;
    };

    users.users."noisebridge".openssh.authorizedKeys.keys = [
      # replace with your ssh key 
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK9tjvxDXYRrYX6oDlWI0/vbuib9JOwAooA+gbyGG/+Q robertwendt@Roberts-Laptop.local"
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEGFBq/gMzcNyKiYyo4lklSAl+IFZed2HEhhN5CpMg7m alice@nixos"
    ];

  };
}
