{
  description = "unlock: time-boxed credential-injecting proxy backed by 1Password";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: {
        # The shebang points at babashka in the store, so nothing on PATH can
        # stand in for the interpreter.
        default = pkgs.writeTextFile {
          name = "unlock";
          destination = "/bin/unlock";
          executable = true;
          text = "#!${pkgs.babashka-unwrapped}/bin/bb\n"
            + nixpkgs.lib.removePrefix "#!/usr/bin/env bb\n" (builtins.readFile ./unlock.clj);
        };
      });

      checks = forAll (pkgs: {
        default = pkgs.runCommand "unlock-tests" { nativeBuildInputs = [ pkgs.babashka-unwrapped ]; } ''
          cp -r ${./.}/. . && chmod -R u+w .
          export HOME=$TMPDIR
          bb test
          touch $out
        '';
      });

      darwinModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.programs.unlock;
          json = pkgs.formats.json { };
        in
        {
          options.programs.unlock = {
            enable = lib.mkEnableOption "unlock, a time-boxed credential-injecting proxy";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "The unlock package.";
            };

            services = lib.mkOption {
              type = json.type;
              default = { };
              description = ''
                Services unlock can front, keyed by name. Same shape as
                services.example.edn, with strings for keywords:
                auth.type = "oth-client", allow = [ [ "get" "/api/**" ] ].
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            # Root-owned /usr/local/bin/op, which is both what the 1Password app's
            # CLI integration requires and what unlock's integrity check wants.
            programs._1password.enable = true;

            environment.systemPackages = [ cfg.package ];

            environment.etc."unlock/services.json".source = json.generate "unlock-services.json" {
              op-bin = "/usr/local/bin/op";
              services = cfg.services;
            };

            # Defined in /etc/zprofile (root-owned) so a stray `unlock` earlier on
            # PATH, e.g. in ~/.local/bin, is not what runs.
            environment.shellAliases.unlock = "${cfg.package}/bin/unlock";
          };
        };
    };
}
