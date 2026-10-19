#!/bin/sh
# Installs unlock and its config root-owned, so an agent running as you
# cannot edit them to capture a credential the next time you unlock.
set -eu
cd "$(dirname "$0")"

bin=/usr/local/bin/unlock
conf_dir=/usr/local/etc/unlock

# Pin the interpreter to an absolute path an agent cannot repoint. A nix
# store path is immutable; re-run this after upgrading babashka.
bb_path=$(readlink -f "$(command -v bb)")
case "$bb_path" in
  /nix/store/*) ;;
  *) [ "$(/usr/bin/stat -f %Su "$bb_path")" = root ] || {
       echo "bb at $bb_path is not root-owned or in the nix store; refusing to pin it" >&2; exit 1; } ;;
esac

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
{ echo "#!$bb_path"; tail -n +2 unlock.clj; } > "$tmp"

sudo install -d -o root -g wheel -m 755 /usr/local/bin "$conf_dir"
sudo install -o root -g wheel -m 755 "$tmp" "$bin"
if [ -e "$conf_dir/services.edn" ]; then
  echo "Kept existing $conf_dir/services.edn (edit with: sudo -e $conf_dir/services.edn)"
else
  sudo install -o root -g wheel -m 644 services.example.edn "$conf_dir/services.edn"
  echo "Installed $conf_dir/services.edn from the example; edit with: sudo -e $conf_dir/services.edn"
fi
echo "Installed $bin (interpreter $bb_path)"
