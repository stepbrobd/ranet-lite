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
      description = "The build this machine runs.";
    };

    settings = lib.mkOption {
      type = format.type;
      default = { };
      example = lib.literalExpression ''
        {
          node = { org = "example"; name = "my-laptop"; };
          auth = {
            key = "/var/lib/ranet-lite/key.pem";
            trust = "/var/lib/ranet-lite/trust.json";
          };
          link = { port = 13000; underlay.bind = true; };
        }
      '';
      description = ''
        The config file, in the schema examples/config.toml documents. The
        daemon refuses a key it does not know, so a typo here stops the daemon
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
      default = "admin";
      description = ''
        The group that may read the control socket. The daemon runs as root
        with this as its primary group and leaves the socket at mode 0660, so
        a member of this group can run the read-only subcommands without being
        root. The socket answers no request that writes.

        The default is a group macOS already has and every administrator is
        in, because nothing here creates one: a group this module declared
        would need a gid of its own to be stable across machines.
      '';
    };

    logFile = lib.mkOption {
      type = lib.types.path;
      default = "/var/log/ranet-lite.log";
      description = ''
        Where launchd writes the daemon's output. There is no journal on this
        platform, and a daemon whose refusals go nowhere is one that looks
        like it started.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    launchd.daemons.ranet-lite = {
      # creating a utun and writing the route table both need root, and the
      # group leaves the control socket readable without it. The daemon
      # creates /var/run/ranet-lite itself, at a mode that group can enter,
      # which is why nothing here makes the directory.
      script = ''
        exec ${lib.getExe cfg.package} daemon --config ${cfg.configFile} --log-level ${cfg.logLevel}
      '';
      serviceConfig = {
        RunAtLoad = true;
        KeepAlive = true;
        StandardOutPath = cfg.logFile;
        StandardErrorPath = cfg.logFile;
        GroupName = cfg.group;
        UserName = "root";
        # shutdown closes every session with a grace period and withdraws the
        # routes it installed. launchd sends SIGTERM and then SIGKILL after
        # this, so a machine that takes longer leaves routes behind.
        ExitTimeOut = 20;
      };
    };
  };
}
