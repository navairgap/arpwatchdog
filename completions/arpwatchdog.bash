# bash completion for arpwatchdog
_arpwatchdog() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="-i --interface -r --replay -p --pcap -f --baseline --state
        --gateway --ignore --no-new-hosts --no-suppress --suppress-window
        --flip-window --flip-changes --max-entries --format --alert-file
        --alert-max-bytes --syslog --webhook --quiet --stats --metrics-file
        --metrics-serve --stats-interval --fail-on --dry-run --debug
        --config --list --export --help --version"
    COMPREPLY=()
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi
    case "${COMP_WORDS[COMP_CWORD-1]}" in
        --format) COMPREPLY=( $(compgen -W "json text csv" -- "$cur") );;
        --export) COMPREPLY=( $(compgen -W "json csv html md" -- "$cur") );;
        --fail-on) COMPREPLY=( $(compgen -W "none critical" -- "$cur") );;
        -f|--baseline|-r|--replay|-p|--pcap|--state|--alert-file|--metrics-file)
            COMPREPLY=( $(compgen -f -- "$cur") );;
        -i|--interface) COMPREPLY=( $(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur") );;
        *) COMPREPLY=( $(compgen -W "$opts" -- "$cur") );;
    esac
}
complete -o filenames -F _arpwatchdog arpwatchdog
