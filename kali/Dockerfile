FROM kalilinux/kali-rolling

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # === core ===
    base58 \
    binutils \
    file \
    htop \
    less \
    neovim \
    tmux \
    xxd \
    zsh \
    \
    # === productivity ===
    fzf \
    git \
    ripgrep \
    \
    # === scripting ===
    beef \
    jq \
    python3-pip \
    python3-venv \
    \
    # === forensics ===
    binwalk \
    borgbackup \
    exiftool \
    stegcracker \
    steghide \
    \
    # === network ===
    ftp \
    microsocks \
    netcat-openbsd \
    openssh-client \
    openvpn \
    smbclient \
    sshpass \
    telnet \
    \
    # === network diagnostics ===
    dnsutils \
    inetutils-ping \
    traceroute \
    whois \
    \
    # === GUI ===
    dbus-x11 \
    kali-desktop-xfce \
    terminator \
    x11-xserver-utils \
    \
    # === VNC ===
    novnc \
    tigervnc-standalone-server \
    tigervnc-tools \
    websockify \
    \
    # === security tools ===
    burpsuite \
    enum4linux-ng \
    exploitdb \
    exploitdb-papers \
    ffuf \
    ghidra \
    gobuster \
    kali-tools-web \
    seclists \
    sherlock \
    \
    sudo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN tar -xzf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
    -C /usr/share/seclists/Passwords/Leaked-Databases/ && \
    rm -f /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz

RUN ARCH="$(uname -m)" && \
    curl -L "https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.${ARCH}" \
    -o /usr/local/bin/ttyd && \
    chmod +x /usr/local/bin/ttyd

ENV DISPLAY=:1

# === user setup ===
RUN useradd -m -s /usr/bin/zsh kali && \
    echo "kali:kali" | chpasswd && \
    usermod -aG sudo kali && \
    echo "kali ALL=(ALL) NOPASSWD: /usr/sbin/openvpn" >> /etc/sudoers

# === switch to user ===
USER kali
WORKDIR /home/kali

# === Oh My Zsh ===
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

# === Powerlevel10k ===
RUN git clone --depth=1 https://github.com/romkatv/powerlevel10k.git \
    /home/kali/.oh-my-zsh/custom/themes/powerlevel10k

# === tmux plugins ===
RUN git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm && \
    git clone https://github.com/tmux-plugins/tmux-resurrect ~/.tmux/plugins/tmux-resurrect

# === enhancd ===
RUN git clone https://github.com/b4b4r07/enhancd.git /home/kali/.enhancd && \
    echo 'export ENHANCD_DIR=$HOME/.enhancd' >> /home/kali/.zshrc && \
    echo 'source $ENHANCD_DIR/init.sh' >> /home/kali/.zshrc && \
    chown -R kali:kali /home/kali/.enhancd /home/kali/.zshrc
