flakePkgs:
{ config, lib, pkgs, self, ... }:
let
  cfg = config.networking.networkmanager.ensureProfiles.secrets;
  toml = pkgs.formats.toml {};

  configFileData = {
    entry = builtins.map
      (i: {
        key = i.key;
        file = i.file;
        }
        // lib.optionalAttrs (i.matchId != null) { match_id = i.matchId; }
        // lib.optionalAttrs (i.matchUuid != null) { match_uuid = i.matchUuid; }
        // lib.optionalAttrs (i.matchType != null) { match_type = i.matchType; }
        // lib.optionalAttrs (i.matchIface != null) { match_iface = i.matchIface; }
        // lib.optionalAttrs (i.matchSetting != null) { match_setting = i.matchSetting; }
      )
      cfg.entries;
  };
  configFile = toml.generate "config.toml" configFileData;
in {
  options.networking.networkmanager.ensureProfiles.secrets = {
    enable = lib.mkEnableOption "an agent that automatically fills secrets into profiles upon request" // {
      defaultText = "true if any entries are configured, false otherwise";
      default = (lib.length cfg.entries) > 0;
    };
    package = lib.mkPackageOption flakePkgs."${pkgs.stdenv.system}" "nm-file-secret-agent" {
      pkgsText = "self.packages";
    };
    entries = lib.mkOption {
      description = "The secrets to provide";
      default = [];
      type = lib.types.listOf (lib.types.submodule {
        options = {
          matchId = lib.mkOption {
            description = "network manager connection id (displayed as name in GUIs)";
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          matchUuid = lib.mkOption {
            description = "network manager connection uuid";
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          matchType = lib.mkOption {
            description = "network manager connection type";
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          matchIface = lib.mkOption {
            description = "interface name of the network manager connection";
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          matchSetting = lib.mkOption {
            description = "name of the setting section for which secrets are requested";
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          key = lib.mkOption {
            description = "key in the setting section for which entry provides a value";
            type = lib.types.str;
          };
          file = lib.mkOption {
            description = "file from which the secret value is read";
            type = lib.types.str;
          };
        };
      });
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services."nm-file-secret-agent" = {
      description = "NetworkManager secret agent that responds with the content of preconfigured files";
      documentation = [ "https://git.lly.sh/ftsell/nm-file-secret-agent" ];
      requires = [ "NetworkManager.service" ];
      after = [ "NetworkManager.service" ];
      wantedBy = ["multi-user.target"];
      restartTriggers = [ configFile ];
      script = "${lib.getExe cfg.package} --conf ${configFile}";
    };
  };
}
