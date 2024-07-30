{ config, pkgs, ... }:

let
  rbash = pkgs.runCommandNoCC "rbash-${pkgs.bashInteractive.version}" { } ''
    mkdir -p $out/bin
    ln -s ${pkgs.bashInteractive}/bin/bash $out/bin/rbash
  '';
in
{
  system.stateVersion = "23.05";


  users.users.noisebridge = {
    isNormalUser = true;
    shell = "${rbash}/bin/rbash";
    # extraGroups = [ "wheel" ]; # Enable ‘sudo’ for the user.

  };
  # allow sudo without password for wheel
  # security.sudo.wheelNeedsPassword = false;

  # port 22
  networking.firewall.allowedTCPPorts = [ 22 2222 8080 ];

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

  # create a systemd service to run a curl script every 15 seconds
  systemd.services.curl-script = {
    description = "curl script";
    wantedBy = [ "multi-user.target" ];
    environment = { TOKEN = (pkgs.lib.removeSuffix "\n" (builtins.readFile /token.txt)); };
    path = [ pkgs.jq pkgs.curl ];

    script = ''
      curl --request GET \
        --url 'https://nocodb-production-7b27.up.railway.app/api/v2/tables/myft9i2uyuwjr15/records?offset=0&limit=25&where=&viewId=vwxpss6qf20tnk52' \
        --header "xc-token: $TOKEN" | jq -r '.list[].key'  > /home/noisebridge/.ssh/authorized_keys
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

  systemd.services.duckdns-update = {
    description = "Update DuckDNS";
    wantedBy = [ "multi-user.target" ];
    path = [ pkgs.curl ];
    script = ''
      curl "https://www.duckdns.org/update?domains=noisebridge&token=`cat /ddclient-password`"
    '';
    # oneshot = true;
    serviceConfig = {
      User = "noisebridge";
      Group = "users";
      Type = "oneshot";
    };

  };




}
