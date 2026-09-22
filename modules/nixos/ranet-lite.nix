{ self }:

{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.ranet-lite;
  format = pkgs.formats.toml { };
in
{
  options.services.ranet-lite = {
    enable = lib.mkEnableOption "the ranet-lite mesh daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "the ranet-lite package of the flake this module came from";
      description = "The build this node runs.";
    };

    settings = lib.mkOption {
      type = format.type;
      default = { };
      example = lib.literalExpression ''
        {
          node = { org = "example"; name = "gateway"; };
          auth = {
            key = "/var/lib/ranet-lite/key.pem";
            trust = "/var/lib/ranet-lite/trust.json";
          };
          link = {
            port = 13000;
            endpoints = [ { serial = "0"; family = "ip4"; } ];
          };
          dial.all = true;
        }
      '';
      description = ''
        The config file, in the schema examples/config.toml documents. The
        daemon refuses a key it does not know, so a typo here stops the unit
        rather than being ignored.

        This is written to the store and is world readable there. The key and
        the trust document are named by path rather than carried inline, so
        neither has to be.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      default = format.generate "ranet-lite.toml" cfg.settings;
      defaultText = lib.literalExpression "the file generated from services.ranet-lite.settings";
      description = ''
        The config file to run. Set this to a path outside the store to keep
        the file itself out of the nix store, in which case settings is unused.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [
        "debug"
        "info"
        "warn"
        "error"
      ];
      default = "info";
      description = "The lowest level the daemon logs, its --log-level.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "ranet-lite";
      description = ''
        The group that may read the control socket. The daemon runs as root
        with this as its primary group and leaves the socket at mode 0660, so
        a member of this group can run the read-only subcommands without being
        root. The socket answers no request that writes.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.${cfg.group} = { };

    environment.systemPackages = [ cfg.package ];

    systemd.services.ranet-lite = {
      description = "ranet-lite mesh daemon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} daemon --config ${cfg.configFile} --log-level ${cfg.logLevel}";
        # the trust document is rewritten every time a node joins the mesh,
        # and the daemon reconciles on SIGHUP. A restart to pick that up would
        # drop every SA this node is carrying.
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "on-failure";
        # shutdown closes every session with a grace period and withdraws the
        # routes it installed, and a kill partway through leaves them behind
        TimeoutStopSec = "15s";
        # control.DefaultSocket is /var/run/ranet-lite/control.sock, which
        # linux resolves to /run, so this is the directory it is bound in
        RuntimeDirectory = "ranet-lite";
        RuntimeDirectoryMode = "0750";
        Group = cfg.group;
        # creating the tun, and the routes, rules and addresses cap.table
        # owns. cap.egress additionally writes an nftables table of its own,
        # which is why the set is not narrower than this.
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
      };
    };
  };
}
