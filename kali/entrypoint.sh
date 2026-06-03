#!/bin/bash
set -e

echo "[*] Starting OpenVPN..."
sudo openvpn --config /etc/openvpn/tryhackme.ovpn &


echo "[*] Starting SOCKS5 proxy..."
microsocks -i 0.0.0.0 -p 1080 &


echo "[*] Cleaning VNC locks..."
vncserver -kill :1 2>/dev/null || true
rm -f /tmp/.X*-lock 2>/dev/null || true
rm -rf /tmp/.X11-unix/X* 2>/dev/null || true


echo "[*] Setting VNC password..."
if [ -z "$VNC_PASSWORD" ]; then
  echo "[!] VNC_PASSWORD is not set"
  exit 1
fi
printf "%s\n%s\nn\n" "$VNC_PASSWORD" "$VNC_PASSWORD" | vncpasswd


echo "[*] Starting VNC..."
vncserver :1 -localhost no || echo "[!] VNC failed but continuing"


echo "[*] Starting noVNC..."
websockify --web=/usr/share/novnc 6080 localhost:5901 &


echo "[*] Starting tmux session..."
tmux has-session -t ctf 2>/dev/null || tmux new-session -d -s ctf


echo "[*] Starting ttyd..."
ttyd -W -p 7681 tmux attach -t ctf &


echo "[*] Preparing wordlists..."
ROCKYOU_DIR="/usr/share/seclists/Passwords/Leaked-Databases"
ROCKYOU_TXT="$ROCKYOU_DIR/rockyou.txt"
ROCKYOU_TAR="$ROCKYOU_DIR/rockyou.txt.tar.gz"
if [ ! -f "$ROCKYOU_TXT" ] && [ -f "$ROCKYOU_TAR" ]; then
  echo "[*] Extracting rockyou.txt..."
  sudo tar -xzf "$ROCKYOU_TAR" -C "$ROCKYOU_DIR"
  sudo rm -f "$ROCKYOU_TAR"
fi


echo "[*] System ready."


tail -f /dev/null
