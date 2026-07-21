# ========================
# terminal (256-color backgrounds for p10k, etc.)
# ========================
[[ ${TERM:-} == *256color* ]] || export TERM=xterm-256color

# ========================
# p10k instant prompt
# ========================
if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi

# ========================
# oh-my-zsh
# ========================
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="powerlevel10k/powerlevel10k"

plugins=(
  fzf
  git
  history
  sudo
  tmux
)

source $ZSH/oh-my-zsh.sh

# ========================
# prompt
# ========================
[[ ! -f ~/.p10k.zsh ]] || source ~/.p10k.zsh

# ========================
# core zsh behavior
# ========================

setopt AUTO_CD
setopt ALIASES
unsetopt CORRECT

# ========================
# history config
# ========================

export HISTSIZE=100000
export SAVEHIST=100000

setopt SHARE_HISTORY
setopt HIST_IGNORE_DUPS
setopt HIST_FIND_NO_DUPS
setopt INC_APPEND_HISTORY

# ========================
# completion bootstrap
# ========================

autoload -Uz compinit
compinit

# ========================
# modules
# ========================
source ~/.zsh/load.zsh

# ========================
# user-local tool paths
# ========================
path=(
  "${ASDF_DATA_DIR:-$HOME/.asdf}/shims"
  "$HOME/.local/bin"
  $path
)

# >>> ctx >>>
source <(ctx completion zsh --extra-shortcuts)
# <<< ctx <<<
