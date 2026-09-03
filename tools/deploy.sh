#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
megaproxy_inventory="${MEGAPROXY_INVENTORY:-${HOME:?}/MyProjects/ansible-inventory/mega-proxy-inventory.yml}"
px_manager_target="${PX_MANAGER_TARGET:-px-manager.jethelix.ru}"
px_manager_ssh_user="${PX_MANAGER_SSH_USER:-andre487}"
px_manager_ssh_private_key="${PX_MANAGER_SSH_PRIVATE_KEY:-${HOME:?}/.ssh/id_ecdsa}"

playbook="$project_dir/ansible/deploy.yml"

if [[ ! -f "$megaproxy_inventory" ]]; then
    echo "MegaProxy inventory not found: $megaproxy_inventory" >&2
    exit 1
fi

if [[ ! -f "$playbook" ]]; then
    echo "PX Manager playbook not found: $playbook" >&2
    exit 1
fi

if ! command -v ansible-playbook >/dev/null 2>&1; then
    echo "ansible-playbook is required and was not found in PATH" >&2
    exit 1
fi

command=(
    ansible-playbook
    -i "$px_manager_target,"
    -e "@$megaproxy_inventory"
    "$playbook"
    -e "px_manager_target=$px_manager_target"
    -e "ansible_host=$px_manager_target"
    -e "ansible_user=$px_manager_ssh_user"
    -e "ansible_ssh_private_key_file=$px_manager_ssh_private_key"
)
if [[ -z "${ANSIBLE_VAULT_PASSWORD_FILE:-}" ]] && grep -q '!vault' "$megaproxy_inventory"; then
    command+=(--ask-vault-pass)
fi
command+=("$@")

"${command[@]}"
