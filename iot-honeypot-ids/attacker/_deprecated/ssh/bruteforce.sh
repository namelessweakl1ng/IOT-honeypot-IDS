# SSH scenario scripts
#
# These are wrappers around the lib.sh functions; the heavy lifting lives
# in runner/lib.sh so the run-scenario.sh dispatcher stays simple.

# ssh/bruteforce.sh — called by ssh-bruteforce scenario steps.
# Source: runner/lib.sh must already be sourced.
runner_ssh_bruteforce
