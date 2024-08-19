{ config, pkgs, ... }:

let
  rbash = pkgs.runCommandNoCC "rbash-${pkgs.bashInteractive.version}" { } ''
    mkdir -p $out/bin
    ln -s ${pkgs.bashInteractive}/bin/bash $out/bin/rbash
  '';
  assignEIP = pkgs.writeShellApplication {
    name = "assign-eip";
    runtimeInputs = [ pkgs.awscli2 pkgs.curl ];
    text = ''
      ELASTIC_IP="54.186.174.84"
      INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
      ALLOCATION_ID=$(aws ec2 describe-addresses --public-ips $ELASTIC_IP --query 'Addresses[0].AllocationId' --output text)
      ASSOCIATION_ID=$(aws ec2 describe-addresses --public-ips $ELASTIC_IP --query 'Addresses[0].AssociationId' --output text)

      # Check if the Elastic IP is already associated
      if [ "$ASSOCIATION_ID" != "None" ]; then
        echo "Elastic IP is already associated with another instance. Disassociating..."
        aws ec2 disassociate-address --association-id "$ASSOCIATION_ID"
      fi

      # Assign the Elastic IP to the current instance
      aws ec2 associate-address --instance-id "$INSTANCE_ID" --allocation-id "$ALLOCATION_ID"
    '';
  };
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
  networking.firewall.allowedTCPPorts = [ 22 80 443 ];

  services.openssh = {
    enable = true;
    # require public key authentication for better security
    settings.PasswordAuthentication = false;
    settings.KbdInteractiveAuthentication = false;
    # settings.GatewayPorts = "yes";

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
      mkdir -p /home/noisebridge/.ssh
      curl --request GET \
        --url 'https://nbnoco.duckdns.org/api/v2/tables/mfph3iaygjlimj8/records?offset=0&limit=25&where=&viewId=vwd4iqgj46t17e9e' \
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

  systemd.services.assign-eip = {
    description = "Assign Elastic IP to instance";
    path = with pkgs; [ awscli2 curl ];
    serviceConfig.Type = "oneshot";
    serviceConfig.RemainAfterExit = true;
    serviceConfig.ExecStart = "${assignEIP}/bin/assign-eip";
    serviceConfig.RestartSec = 32; # Delay between retries
    # serviceConfig.StartLimitBurst = 16; # Number of retry attempts
    serviceConfig.StartLimitIntervalSec = 256; # Time window for retry attempts
    serviceConfig.Restart = "on-failure";

  };

  boot.kernel.sysctl = {
    "net.ipv4.ip_unprivileged_port_start" = 0;
  };

}
