FROM kalilinux/kali-rolling

ARG USERNAME=kali
ARG PASSWORD=kali

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # === core ===
    base58 \
    binutils \
    bsdextrautils \
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
    python3-yaml \
    \
    # === forensics ===
    audacity \
    binwalk \
    borgbackup \
    exiftool \
    name-that-hash \
    poppler-utils \
    stegcracker \
    steghide \
    unrar \
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
    tshark \
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
    # === build tools ===
    build-essential \
    golang \
    libbz2-dev \
    libffi-dev \
    libreadline-dev \
    libsqlite3-dev \
    libssl-dev \
    make \
    zlib1g-dev \
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
RUN useradd -m -s /usr/bin/zsh ${USERNAME} && \
    echo "${USERNAME}:${PASSWORD}" | chpasswd && \
    usermod -aG sudo ${USERNAME} && \
    echo "${USERNAME} ALL=(ALL) NOPASSWD: /usr/sbin/openvpn" >> /etc/sudoers

# === switch to user ===
USER ${USERNAME}
WORKDIR /home/${USERNAME}

# === Oh My Zsh ===
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

# === Powerlevel10k ===
RUN git clone --depth=1 https://github.com/romkatv/powerlevel10k.git \
    ~/.oh-my-zsh/custom/themes/powerlevel10k

# === tmux plugins ===
RUN git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm && \
    git clone https://github.com/tmux-plugins/tmux-resurrect ~/.tmux/plugins/tmux-resurrect

# === enhancd ===
RUN git clone https://github.com/b4b4r07/enhancd.git ~/.enhancd && \
    echo 'export ENHANCD_DIR=$HOME/.enhancd' >> ~/.zshrc && \
    echo 'source $ENHANCD_DIR/init.sh' >> ~/.zshrc

# === asdf ===
RUN git clone https://github.com/asdf-vm/asdf.git ~/asdf --branch v0.19.0 && \
    cd ~/asdf && \
    GOPATH="$HOME/.cache/go" GOCACHE="$HOME/.cache/go-build" make && \
    mkdir -p ~/.local/bin && \
    cp asdf ~/.local/bin/asdf && \
    chmod -R u+w "$HOME/.cache/go" "$HOME/.cache/go-build" && \
    rm -rf "$HOME/.cache/go" "$HOME/.cache/go-build" && \
    echo 'export PATH="$HOME/.local/bin:$HOME/.asdf/shims:$PATH"' >> ~/.zshrc && \
    export PATH="$HOME/.local/bin:$HOME/.asdf/shims:$PATH" && \
    asdf plugin add python && \
    asdf install python 2.7.18 && \
    asdf set -u python 2.7.18 && \
    python -m pip install requests beautifulsoup4
