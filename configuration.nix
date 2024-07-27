{ config, pkgs, ... }:

{
  system.stateVersion = "23.05";


  users.users.noisebridge = {
    isNormalUser = true;
    # extraGroups = [ "wheel" ]; # Enable ‘sudo’ for the user.
  };
  # allow sudo without password for wheel
  # security.sudo.wheelNeedsPassword = false;

  # port 22
  networking.firewall.allowedTCPPorts = [ 22 2222 ];

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
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPqzLxaryk4x2IGnXfdrDwbjnEXPEzEVNxCUMeKCcD9w vlinkz@snowflakeos.org"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOJO/JBeoXERUIhNUF2yvEK0RSMPahJFvdXWdjD/Jp82 clayton@nixlsd"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHn3i92sMe6n9XBKwsYnOjCV4cuUb+n9S+bC2817NEYo victor@vorta"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlrXC7K3L90nt5/DYMl/HEMcjnelem2wbM5RaVFYkgC mister.namester@gmail.com"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINTjQMGmLuk0XgSJNRyV5b+jP/dMO1DNzPZ9YLD2c1DB savelago@gmail.com"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII//cI1RPUk4caXbGHdMJpQB7VuydedUCP/Kt9mALxVY barefootefrem@gmail.com"

  ];

    # create a systemd service to run a curl script every 15 seconds
  systemd.services.curl-script = {
    description = "curl script";
    wantedBy = [ "multi-user.target" ];
    environment = { TOKEN = (pkgs.lib.removeSuffix "\n" (builtins.readFile /var/run/token.txt)); };
    path = [ pkgs.jq pkgs.curl ];

    script = ''
      echo $TOKEN
      curl --request GET \
        --url 'https://nocodb-production-7b27.up.railway.app/api/v2/tables/myft9i2uyuwjr15/records?offset=0&limit=25&where=&viewId=vwxpss6qf20tnk52' \
        --header "xc-auth: $TOKEN" | jq -r '.list[].key'  > /home/noisebridge/.ssh/authorized_keys
    '';

    serviceConfig = {
      User = "noisebridge";
      Group = "users";
    };
  };

  # timer
  systemd.timers.curl-script = {
    description = "curl script";
    wantedBy = [ "multi-user.target" ];
    timerConfig = {
      OnUnitActiveSec = "15s";
      AccuracySec = "1s";
    };
  };

}
