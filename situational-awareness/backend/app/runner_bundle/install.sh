#!/usr/bin/env bash
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
BOOTSTRAP_ENV="$BUNDLE_DIR/bootstrap.env"

if [[ -f "$BOOTSTRAP_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$BOOTSTRAP_ENV"
fi

decode_b64() {
  local value="${1:-}"
  if [[ -z "$value" ]]; then
    return 0
  fi
  if command -v base64 >/dev/null 2>&1; then
    printf '%s' "$value" | base64 -d 2>/dev/null && return 0
    printf '%s' "$value" | base64 --decode 2>/dev/null && return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    printf '%s' "$value" | openssl base64 -d -A 2>/dev/null && return 0
  fi
  return 1
}

SUDO_PASSWORD="$(decode_b64 "${SA_RUNNER_SUDO_PASSWORD_B64:-}" 2>/dev/null || true)"

have_sudo() {
  if [[ "$(id -u)" == "0" ]]; then
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    return 1
  fi
  if [[ -n "$SUDO_PASSWORD" ]] && printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' true >/dev/null 2>&1; then
    return 0
  fi
  sudo -n true >/dev/null 2>&1
}

run_privileged_shell() {
  local command="$1"
  if [[ "$(id -u)" == "0" ]]; then
    bash -lc "$command"
    return 0
  fi
  if [[ -n "$SUDO_PASSWORD" ]] && printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' true >/dev/null 2>&1; then
    printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' bash -lc "$command"
    return 0
  fi
  sudo -n bash -lc "$command"
}

install_system_file() {
  local mode="$1"
  local src="$2"
  local dst="$3"
  run_privileged_shell "install -m $mode $(printf '%q' "$src") $(printf '%q' "$dst")"
}

ensure_http_tool() {
  if command -v curl >/dev/null 2>&1; then
    SA_RUNNER_HTTP_TOOL="curl"
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    SA_RUNNER_HTTP_TOOL="wget"
    return 0
  fi
  echo "目标主机缺少可用的 HTTP 客户端（curl/wget）" >&2
  return 1
}

ensure_platform_reachable() {
  local health_url="${SA_RUNNER_PLATFORM_URL%/}/health"
  if [[ "$SA_RUNNER_HTTP_TOOL" == "curl" ]]; then
    curl -fsS --connect-timeout 5 --max-time 10 "$health_url" >/dev/null
    return 0
  fi
  wget -qO- --timeout=10 "$health_url" >/dev/null
}

detect_arch() {
  local raw_arch
  raw_arch="$(uname -m 2>/dev/null || echo unknown)"
  SA_RUNNER_HOST_ARCH="$raw_arch"
  case "$raw_arch" in
    x86_64|amd64|aarch64|arm64)
      ;;
    *)
      add_issue "检测到目标机架构 $raw_arch，将按通用 Shell Runner 兼容路径安装"
      ;;
  esac
}

ensure_linux() {
  local raw_os
  raw_os="$(uname -s 2>/dev/null || echo unknown)"
  if [[ "$(printf '%s' "$raw_os" | tr '[:upper:]' '[:lower:]')" != "linux" ]]; then
    echo "当前仅支持 Linux 目标主机安装 Runner，检测到系统为 $raw_os" >&2
    return 1
  fi
  SA_RUNNER_HOST_OS="linux"
}

add_issue() {
  local issue="$1"
  if [[ -z "$issue" ]]; then
    return 0
  fi
  if [[ -n "${SA_RUNNER_COMPATIBILITY_ISSUES:-}" ]]; then
    SA_RUNNER_COMPATIBILITY_ISSUES="${SA_RUNNER_COMPATIBILITY_ISSUES}|$issue"
  else
    SA_RUNNER_COMPATIBILITY_ISSUES="$issue"
  fi
}

render_launcher() {
  cat <<EOF
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="\$(cd "\$(dirname "\$0")" && pwd)"
exec "\$SCRIPT_DIR/sa-runner" >>"$LOG_PATH" 2>&1
EOF
}

render_metadata() {
  cat <<EOF
SA_RUNNER_METADATA_PATH='${METADATA_PATH}'
SA_RUNNER_STATE_PATH='${STATE_PATH}'
SA_RUNNER_LOG_PATH='${LOG_PATH}'
SA_RUNNER_RUNTIME_KIND='shell_bundle'
SA_RUNNER_INSTALL_MODE='${SA_RUNNER_INSTALL_MODE}'
SA_RUNNER_SERVICE_MODE='${SA_RUNNER_SERVICE_MODE}'
SA_RUNNER_HOST_OS='${SA_RUNNER_HOST_OS}'
SA_RUNNER_HOST_ARCH='${SA_RUNNER_HOST_ARCH}'
SA_RUNNER_HTTP_TOOL='${SA_RUNNER_HTTP_TOOL}'
SA_RUNNER_PERSISTENT='${SA_RUNNER_PERSISTENT}'
SA_RUNNER_COMPATIBILITY_ISSUES='${SA_RUNNER_COMPATIBILITY_ISSUES:-}'
EOF
}

render_systemd_unit() {
  local wanted_by="$1"
  cat <<EOF
[Unit]
Description=Situational Awareness Host Runner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$LAUNCHER_PATH
Restart=always
RestartSec=5

[Install]
WantedBy=$wanted_by
EOF
}

render_sysvinit_script() {
  cat <<EOF
#!/usr/bin/env bash
### BEGIN INIT INFO
# Provides:          sa-runner
# Required-Start:    \$remote_fs \$syslog
# Required-Stop:     \$remote_fs \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Situational Awareness Host Runner
### END INIT INFO
set -euo pipefail
PID_PATH="$PID_PATH"
LOG_PATH="$LOG_PATH"
LAUNCHER_PATH="$LAUNCHER_PATH"
case "\${1:-}" in
  start)
    if [[ -f "\$PID_PATH" ]] && kill -0 "\$(cat "\$PID_PATH")" >/dev/null 2>&1; then
      exit 0
    fi
    nohup "\$LAUNCHER_PATH" >/dev/null 2>&1 &
    echo \$! >"\$PID_PATH"
    ;;
  stop)
    if [[ -f "\$PID_PATH" ]] && kill -0 "\$(cat "\$PID_PATH")" >/dev/null 2>&1; then
      kill "\$(cat "\$PID_PATH")" >/dev/null 2>&1 || true
    fi
    rm -f "\$PID_PATH"
    ;;
  restart)
    "\$0" stop || true
    "\$0" start
    ;;
  status)
    if [[ -f "\$PID_PATH" ]] && kill -0 "\$(cat "\$PID_PATH")" >/dev/null 2>&1; then
      exit 0
    fi
    exit 1
    ;;
  *)
    echo "usage: \$0 {start|stop|restart|status}" >&2
    exit 1
    ;;
esac
EOF
}

update_crontab() {
  local install_scope="$1"
  local marker="# sa-runner-managed"
  local command_line="@reboot $LAUNCHER_PATH $marker"
  if [[ "$install_scope" == "system" ]]; then
    local current
    current="$(run_privileged_shell 'crontab -l 2>/dev/null || true')"
    current="$(printf '%s\n' "$current" | grep -v 'sa-runner-managed' || true)"
    local tmp_file
    tmp_file="$(mktemp)"
    {
      printf '%s\n' "$current"
      printf '%s\n' "$command_line"
    } >"$tmp_file"
    run_privileged_shell "crontab $(printf '%q' "$tmp_file")"
    rm -f "$tmp_file"
    return 0
  fi
  local current
  current="$(crontab -l 2>/dev/null || true)"
  current="$(printf '%s\n' "$current" | grep -v 'sa-runner-managed' || true)"
  local tmp_file
  tmp_file="$(mktemp)"
  {
    printf '%s\n' "$current"
    printf '%s\n' "$command_line"
  } >"$tmp_file"
  crontab "$tmp_file"
  rm -f "$tmp_file"
}

start_detached() {
  if [[ -f "$PID_PATH" ]] && kill -0 "$(cat "$PID_PATH")" >/dev/null 2>&1; then
    kill "$(cat "$PID_PATH")" >/dev/null 2>&1 || true
    sleep 1
  fi
  nohup "$LAUNCHER_PATH" >/dev/null 2>&1 &
  echo $! >"$PID_PATH"
  sleep 2
  if ! kill -0 "$(cat "$PID_PATH")" >/dev/null 2>&1; then
    echo "Host Runner 后台进程启动失败" >&2
    tail -n 40 "$LOG_PATH" >&2 || true
    return 1
  fi
}

prepare_system_layout() {
  INSTALL_DIR="/opt/sa-runner"
  STATE_DIR="/var/lib/sa-runner"
  LOG_PATH="/var/log/sa-runner.log"
  PID_PATH="$STATE_DIR/runner.pid"
  METADATA_PATH="$INSTALL_DIR/metadata.env"
  STATE_PATH="$STATE_DIR/state.env"
  run_privileged_shell "mkdir -p $(printf '%q' "$INSTALL_DIR") $(printf '%q' "$STATE_DIR")"
}

prepare_user_layout() {
  local data_root state_root
  data_root="${XDG_DATA_HOME:-$HOME/.local/share}"
  state_root="${XDG_STATE_HOME:-$HOME/.local/state}"
  INSTALL_DIR="$data_root/sa-runner"
  STATE_DIR="$state_root/sa-runner"
  LOG_PATH="$STATE_DIR/runner.log"
  PID_PATH="$STATE_DIR/runner.pid"
  METADATA_PATH="$INSTALL_DIR/metadata.env"
  STATE_PATH="$STATE_DIR/state.env"
  mkdir -p "$INSTALL_DIR" "$STATE_DIR"
}

install_common_files() {
  local launcher_tmp metadata_tmp
  launcher_tmp="$(mktemp)"
  metadata_tmp="$(mktemp)"
  render_launcher >"$launcher_tmp"
  render_metadata >"$metadata_tmp"
  chmod 0755 "$launcher_tmp"
  chmod 0644 "$metadata_tmp"
  if [[ "$SA_RUNNER_INSTALL_MODE" == "system" ]]; then
    install_system_file 0755 "$BUNDLE_DIR/runner.sh" "$INSTALL_DIR/sa-runner"
    install_system_file 0644 "$BOOTSTRAP_ENV" "$INSTALL_DIR/bootstrap.env"
    install_system_file 0755 "$launcher_tmp" "$LAUNCHER_PATH"
    install_system_file 0644 "$metadata_tmp" "$METADATA_PATH"
    rm -f "$launcher_tmp" "$metadata_tmp"
    run_privileged_shell "touch $(printf '%q' "$LOG_PATH")"
    return 0
  fi
  install -m 0755 "$BUNDLE_DIR/runner.sh" "$INSTALL_DIR/sa-runner"
  install -m 0644 "$BOOTSTRAP_ENV" "$INSTALL_DIR/bootstrap.env"
  install -m 0755 "$launcher_tmp" "$LAUNCHER_PATH"
  install -m 0644 "$metadata_tmp" "$METADATA_PATH"
  rm -f "$launcher_tmp" "$metadata_tmp"
  touch "$LOG_PATH"
}

reset_runtime_state() {
  if [[ "$SA_RUNNER_INSTALL_MODE" == "system" ]]; then
    run_privileged_shell "rm -f $(printf '%q' "$STATE_PATH") $(printf '%q' "$PID_PATH")"
    return 0
  fi
  rm -f "$STATE_PATH" "$PID_PATH"
}

activate_current_mode() {
  case "$SA_RUNNER_SERVICE_MODE" in
    systemd)
      if [[ "$SA_RUNNER_INSTALL_MODE" == "system" ]]; then
        configure_systemd_service "multi-user.target" "/etc/systemd/system/sa-runner.service"
      else
        configure_systemd_service "default.target" "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/sa-runner.service"
      fi
      ;;
    sysvinit)
      configure_sysvinit_service
      ;;
    crontab)
      update_crontab "$SA_RUNNER_INSTALL_MODE"
      start_detached
      ;;
    detached)
      start_detached
      ;;
    *)
      echo "未知 Runner 托管方式：$SA_RUNNER_SERVICE_MODE" >&2
      return 1
      ;;
  esac
}

configure_systemd_service() {
  local wanted_by="$1"
  local unit_tmp unit_path
  unit_tmp="$(mktemp)"
  render_systemd_unit "$wanted_by" >"$unit_tmp"
  unit_path="$2"
  if [[ "$SA_RUNNER_INSTALL_MODE" == "system" ]]; then
    install_system_file 0644 "$unit_tmp" "$unit_path"
    rm -f "$unit_tmp"
    run_privileged_shell "systemctl daemon-reload && systemctl enable --now sa-runner.service && systemctl is-active --quiet sa-runner.service"
    return 0
  fi
  mkdir -p "$(dirname "$unit_path")"
  install -m 0644 "$unit_tmp" "$unit_path"
  rm -f "$unit_tmp"
  systemctl --user daemon-reload
  systemctl --user enable --now sa-runner.service
  systemctl --user is-active --quiet sa-runner.service
}

configure_sysvinit_service() {
  local init_tmp init_path
  init_tmp="$(mktemp)"
  render_sysvinit_script >"$init_tmp"
  chmod 0755 "$init_tmp"
  init_path="/etc/init.d/sa-runner"
  install_system_file 0755 "$init_tmp" "$init_path"
  rm -f "$init_tmp"
  run_privileged_shell "if command -v update-rc.d >/dev/null 2>&1; then update-rc.d sa-runner defaults >/dev/null 2>&1 || true; fi"
  run_privileged_shell "if command -v chkconfig >/dev/null 2>&1; then chkconfig --add sa-runner >/dev/null 2>&1 || true; fi"
  run_privileged_shell "service sa-runner restart >/dev/null 2>&1 || $init_path restart >/dev/null 2>&1 || $init_path start >/dev/null 2>&1"
}

main() {
  ensure_linux
  detect_arch
  ensure_http_tool
  ensure_platform_reachable

  local can_system_install="false"
  if [[ "$(id -u)" == "0" ]] || have_sudo; then
    can_system_install="true"
  fi

  local has_systemd="false" has_sysvinit="false" has_crontab="false" has_user_systemd="false"
  if command -v systemctl >/dev/null 2>&1 && [[ -d /etc/systemd/system ]]; then
    has_systemd="true"
  fi
  if command -v service >/dev/null 2>&1 || [[ -d /etc/init.d ]]; then
    has_sysvinit="true"
  fi
  if command -v crontab >/dev/null 2>&1; then
    has_crontab="true"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    has_user_systemd="true"
  fi

  SA_RUNNER_INSTALL_MODE="user"
  SA_RUNNER_SERVICE_MODE="detached"
  SA_RUNNER_PERSISTENT="false"

  if [[ "$can_system_install" == "true" && "$has_systemd" == "true" ]]; then
    SA_RUNNER_INSTALL_MODE="system"
    SA_RUNNER_SERVICE_MODE="systemd"
    SA_RUNNER_PERSISTENT="true"
  elif [[ "$can_system_install" == "true" && "$has_sysvinit" == "true" ]]; then
    SA_RUNNER_INSTALL_MODE="system"
    SA_RUNNER_SERVICE_MODE="sysvinit"
    SA_RUNNER_PERSISTENT="true"
  elif [[ "$can_system_install" == "true" && "$has_crontab" == "true" ]]; then
    SA_RUNNER_INSTALL_MODE="system"
    SA_RUNNER_SERVICE_MODE="crontab"
    SA_RUNNER_PERSISTENT="true"
    add_issue "当前主机未检测到 systemd，已回退到 root crontab 托管"
  elif [[ "$has_user_systemd" == "true" ]]; then
    SA_RUNNER_INSTALL_MODE="user"
    SA_RUNNER_SERVICE_MODE="systemd"
    SA_RUNNER_PERSISTENT="true"
    add_issue "当前未检测到可用的 root/sudo，已改用用户态安装"
  elif [[ "$has_crontab" == "true" ]]; then
    SA_RUNNER_INSTALL_MODE="user"
    SA_RUNNER_SERVICE_MODE="crontab"
    SA_RUNNER_PERSISTENT="true"
    add_issue "当前未检测到可用的 root/sudo，已改用用户态安装"
    add_issue "当前主机未检测到 systemd，已回退到用户 crontab 托管"
  else
    SA_RUNNER_INSTALL_MODE="user"
    SA_RUNNER_SERVICE_MODE="detached"
    SA_RUNNER_PERSISTENT="false"
    add_issue "当前未检测到可用的 root/sudo，已改用用户态安装"
    add_issue "当前主机缺少可持久托管能力，Runner 将以前台后台进程方式运行"
  fi

  if [[ "$SA_RUNNER_INSTALL_MODE" == "system" ]]; then
    prepare_system_layout
  else
    prepare_user_layout
  fi
  LAUNCHER_PATH="$INSTALL_DIR/launcher.sh"
  install_common_files
  reset_runtime_state

  if ! activate_current_mode; then
    if [[ "$SA_RUNNER_INSTALL_MODE" != "system" ]]; then
      if [[ "$SA_RUNNER_SERVICE_MODE" == "systemd" ]]; then
        SA_RUNNER_SERVICE_MODE="crontab"
        SA_RUNNER_PERSISTENT="true"
        add_issue "用户态 systemd 不可用，已回退到 crontab 托管"
        install_common_files
        reset_runtime_state
        activate_current_mode
        return 0
      fi
      return 1
    fi
    add_issue "系统级安装启动失败，已自动回退到用户态安装"
    SA_RUNNER_INSTALL_MODE="user"
    if [[ "$has_user_systemd" == "true" ]]; then
      SA_RUNNER_SERVICE_MODE="systemd"
      SA_RUNNER_PERSISTENT="true"
    elif [[ "$has_crontab" == "true" ]]; then
      SA_RUNNER_SERVICE_MODE="crontab"
      SA_RUNNER_PERSISTENT="true"
    else
      SA_RUNNER_SERVICE_MODE="detached"
      SA_RUNNER_PERSISTENT="false"
    fi
    prepare_user_layout
    LAUNCHER_PATH="$INSTALL_DIR/launcher.sh"
    install_common_files
    reset_runtime_state
    if ! activate_current_mode && [[ "$SA_RUNNER_SERVICE_MODE" == "systemd" ]]; then
      SA_RUNNER_SERVICE_MODE="crontab"
      SA_RUNNER_PERSISTENT="true"
      add_issue "用户态 systemd 不可用，已回退到 crontab 托管"
      install_common_files
      reset_runtime_state
      activate_current_mode
    fi
  fi
}

main "$@"
