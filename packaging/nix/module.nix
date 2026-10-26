{ config, lib, pkgs, ... }:
let
  cfg = config.services.httpjet;
  args = [ "${cfg.package}/bin/httpjet" "--root" cfg.configRoot "serve"
    "--http-addr" cfg.httpAddress "--https-addr=${cfg.httpsAddress}"
    "--metrics-addr=" "--no-php" ] ++ lib.optional cfg.noMultishotAccept "--no-multishot-accept" ++ cfg.extraArgs;
in {
  options.services.httpjet = {
    enable = lib.mkEnableOption "the httpjet web server";
    package = lib.mkOption { type = lib.types.package; description = "Hash-pinned package made with packaging/nix/package.nix."; };
    configRoot = lib.mkOption { type = lib.types.str; default = "/etc/httpjet"; };
    httpAddress = lib.mkOption { type = lib.types.str; default = "0.0.0.0:80"; };
    httpsAddress = lib.mkOption { type = lib.types.str; default = ""; };
    noMultishotAccept = lib.mkOption { type = lib.types.bool; default = true; };
    extraGroups = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; };
    extraArgs = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; };
  };
  config = lib.mkIf cfg.enable {
    users.groups.httpjet = {};
    users.users.httpjet = { isSystemUser = true; group = "httpjet"; home = "/var/lib/httpjet"; extraGroups = cfg.extraGroups; };
    environment.etc."httpjet/conf".source = "${cfg.package}/share/httpjet/conf";
    system.activationScripts.httpjet-seed = {
      deps = [];
      text = ''
        marker_dir=/var/lib/httpjet-installation
        if [ -L "$marker_dir" ]; then
          echo "httpjet: installation state directory is a symlink" >&2
          exit 1
        fi
        ${pkgs.coreutils}/bin/install -d -m0700 -o root -g root "$marker_dir"
        if [ ! -e "$marker_dir/declarative-initialized" ]; then
          if [ ! -e /var/www/httpjet ] && [ ! -L /var/www/httpjet ]; then
            ${pkgs.coreutils}/bin/mkdir -p /var/www
            if ${pkgs.coreutils}/bin/mkdir -m0755 /var/www/httpjet; then
              ${pkgs.coreutils}/bin/install -m0644 ${cfg.package}/share/httpjet/welcome/index.html /var/www/httpjet/index.html
            fi
          fi
          (umask 077; printf 'initialized\n' > "$marker_dir/declarative-initialized")
        fi
      '';
    };
    systemd.services.httpjet = {
      description = "httpjet web server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      environment = { HTTPJET_LOG_DIR = "/var/log/httpjet"; RUST_LOG = "httpjet=info"; };
      serviceConfig = {
        Type = "notify"; NotifyAccess = "main";
        User = "httpjet"; Group = "httpjet";
        ExecStartPre = lib.escapeShellArgs [ "${cfg.package}/bin/httpjet" "--root" cfg.configRoot "check" "--strict" ];
        ExecStart = lib.escapeShellArgs args;
        WorkingDirectory = "/var/lib/httpjet";
        RuntimeDirectory = "httpjet"; RuntimeDirectoryMode = "0750";
        StateDirectory = "httpjet"; StateDirectoryMode = "0750";
        LogsDirectory = "httpjet"; LogsDirectoryMode = "0750";
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        NoNewPrivileges = true; ProtectSystem = "strict"; ProtectHome = true;
        PrivateTmp = true; PrivateDevices = true; RestrictSUIDSGID = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        LimitNOFILE = 65536; LimitMEMLOCK = 8388608;
        UMask = "0027"; Restart = "on-failure"; RestartSec = 2;
        TimeoutStartSec = 30; TimeoutStopSec = 30;
      };
    };
  };
}
