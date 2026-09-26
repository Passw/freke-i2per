{ pkgs, lib, config, ... }:

{
  cachix.enable = false;

  languages = {
    erlang.enable = true;
    javascript = {
      enable = true;
      npm.enable = true;
    };
  };
  packages = [ pkgs.just pkgs.jujutsu pkgs.git pkgs.erlfmt pkgs.erlang-language-platform pkgs.gh ];

  enterShell = ''
    # gh asks the terminal for its background colour (OSC 11). Terminals that
    # answer it leak the reply into the tty input queue, where it surfaces as
    # junk at the prompt and can swallow the first keystrokes typed afterwards.
    # muesli/termenv skips the query entirely when TERM begins with "screen",
    # "tmux" or "dumb" — and keeps 256-colour output for anything containing
    # "256color", which "dumb" would not. Scoped to gh so nothing else is told a
    # lie about its TERM. Remove if gh ever stops querying the terminal.
    gh() { TERM=screen-256color command gh "$@"; }

    # Exported, not merely defined: devenv's generated hook ends in `exec "$@"`,
    # and the exec'd login shell inherits exported functions from the
    # environment but not plain definitions. Verified: without this line,
    # `type gh` in a devenv shell reports the binary path.
    export -f gh
  '';

  enterTest = ''
    rebar3 eunit
  '';
}
