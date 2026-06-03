FROM kalilinux/kali-rolling

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # === basic tools ===
    binutils \
    dnsutils \
    exiftool \
    file \
    fzf \
    git \
    htop \
    inetutils-ping \
    jq \
    neovim \
    netcat-openbsd \
    openssh-client \
    python3-pip \
    ripgrep \
    smbclient \
    telnet \
    tmux \
    traceroute \
    whois \
    zsh \
    \
    # === network ===
    microsocks \
    openvpn \
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
    ffuf \
    gobuster \
    kali-tools-web \
    seclists \
    \
    sudo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

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
