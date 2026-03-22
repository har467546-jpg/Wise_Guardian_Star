#!/usr/bin/env sh
set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BOOTSTRAP_ENV="$SCRIPT_DIR/bootstrap.env"
METADATA_ENV="${SA_RUNNER_METADATA_PATH:-$SCRIPT_DIR/metadata.env}"

if [ -f "$BOOTSTRAP_ENV" ]; then
  # shellcheck disable=SC1090
  . "$BOOTSTRAP_ENV"
fi

if [ -f "$METADATA_ENV" ]; then
  # shellcheck disable=SC1090
  . "$METADATA_ENV"
fi

STATE_PATH="${SA_RUNNER_STATE_PATH:-$SCRIPT_DIR/${SA_RUNNER_DEFAULT_STATE_FILE:-state.env}}"
SA_RUNNER_PLATFORM_URL="${SA_RUNNER_PLATFORM_URL:-}"
SA_RUNNER_REGISTRATION_TOKEN="${SA_RUNNER_REGISTRATION_TOKEN:-}"
SA_RUNNER_VERSION="${SA_RUNNER_VERSION:-2.0.0}"
SA_RUNNER_POLL_INTERVAL_SECONDS="${SA_RUNNER_POLL_INTERVAL_SECONDS:-10}"
SA_RUNNER_RUNTIME_KIND="${SA_RUNNER_RUNTIME_KIND:-shell_bundle}"
SA_RUNNER_INSTALL_MODE="${SA_RUNNER_INSTALL_MODE:-user}"
SA_RUNNER_SERVICE_MODE="${SA_RUNNER_SERVICE_MODE:-detached}"
SA_RUNNER_HOST_OS="${SA_RUNNER_HOST_OS:-linux}"
SA_RUNNER_HOST_ARCH="${SA_RUNNER_HOST_ARCH:-unknown}"
SA_RUNNER_PERSISTENT="${SA_RUNNER_PERSISTENT:-false}"
SA_RUNNER_HTTP_TOOL="${SA_RUNNER_HTTP_TOOL:-}"
SA_RUNNER_COMPATIBILITY_ISSUES="${SA_RUNNER_COMPATIBILITY_ISSUES:-}"
SA_RUNNER_TOKEN="${SA_RUNNER_TOKEN:-}"
SA_RUNNER_RUNNER_ID="${SA_RUNNER_RUNNER_ID:-${SA_RUNNER_ID:-}}"

if [ -f "$STATE_PATH" ]; then
  # shellcheck disable=SC1090
  . "$STATE_PATH"
fi

detect_http_tool() {
  if [ -n "$SA_RUNNER_HTTP_TOOL" ]; then
    return 0
  fi
  if command -v curl >/dev/null 2>&1; then
    SA_RUNNER_HTTP_TOOL="curl"
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    SA_RUNNER_HTTP_TOOL="wget"
    return 0
  fi
  echo "Runner 缺少可用的 HTTP 客户端（curl/wget）" >&2
  return 1
}

json_escape() {
  printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_quote() {
  printf '"%s"' "$(json_escape "${1:-}")"
}

json_string_or_null() {
  if [ -n "${1:-}" ]; then
    json_quote "$1"
  else
    printf 'null'
  fi
}

json_array_from_pipe_list() {
  old_ifs="$IFS"
  IFS='|'
  json_items=""
  for item in ${1:-}; do
    [ -n "$item" ] || continue
    item_json="$(json_quote "$item")"
    if [ -n "$json_items" ]; then
      json_items="$json_items,$item_json"
    else
      json_items="$item_json"
    fi
  done
  IFS="$old_ifs"
  printf '[%s]' "$json_items"
}

json_get_string() {
  key="$1"
  payload="$2"
  printf '%s' "$payload" | tr -d '\n' | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

json_get_number() {
  key="$1"
  payload="$2"
  printf '%s' "$payload" | tr -d '\n' | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" | head -n 1
}

decode_b64() {
  value="${1:-}"
  if [ -z "$value" ]; then
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

write_state() {
  state_dir="$(dirname "$STATE_PATH")"
  mkdir -p "$state_dir"
  tmp_file="$(mktemp "${STATE_PATH}.tmp.XXXXXX")"
  {
    printf "SA_RUNNER_TOKEN=%s\n" "$(printf '%s' "${SA_RUNNER_TOKEN:-}" | sed "s/'/'\\\\''/g; 1s/^/'/; \$s/\$/'/")"
    printf "SA_RUNNER_RUNNER_ID=%s\n" "$(printf '%s' "${SA_RUNNER_RUNNER_ID:-}" | sed "s/'/'\\\\''/g; 1s/^/'/; \$s/\$/'/")"
    printf "SA_RUNNER_POLL_INTERVAL_SECONDS=%s\n" "$(printf '%s' "${SA_RUNNER_POLL_INTERVAL_SECONDS:-10}" | sed "s/'/'\\\\''/g; 1s/^/'/; \$s/\$/'/")"
  } >"$tmp_file"
  mv "$tmp_file" "$STATE_PATH"
}

http_json() {
  method="$1"
  path="$2"
  body="${3:-}"
  url="${SA_RUNNER_PLATFORM_URL%/}$path"
  if [ "$SA_RUNNER_HTTP_TOOL" = "curl" ]; then
    if [ -n "$body" ]; then
      if [ -n "${SA_RUNNER_TOKEN:-}" ]; then
        curl -fsS --connect-timeout 5 --max-time 30 -X "$method" -H "Content-Type: application/json" -H "X-Runner-Token: $SA_RUNNER_TOKEN" --data "$body" "$url"
      else
        curl -fsS --connect-timeout 5 --max-time 30 -X "$method" -H "Content-Type: application/json" --data "$body" "$url"
      fi
    else
      if [ -n "${SA_RUNNER_TOKEN:-}" ]; then
        curl -fsS --connect-timeout 5 --max-time 30 -X "$method" -H "Content-Type: application/json" -H "X-Runner-Token: $SA_RUNNER_TOKEN" "$url"
      else
        curl -fsS --connect-timeout 5 --max-time 30 -X "$method" -H "Content-Type: application/json" "$url"
      fi
    fi
    return $?
  fi
  if [ -n "$body" ]; then
    if [ -n "${SA_RUNNER_TOKEN:-}" ]; then
      wget -qO- --timeout=30 --header="Content-Type: application/json" --header="X-Runner-Token: $SA_RUNNER_TOKEN" --post-data="$body" "$url"
    else
      wget -qO- --timeout=30 --header="Content-Type: application/json" --post-data="$body" "$url"
    fi
  else
    if [ -n "${SA_RUNNER_TOKEN:-}" ]; then
      wget -qO- --timeout=30 --header="Content-Type: application/json" --header="X-Runner-Token: $SA_RUNNER_TOKEN" "$url"
    else
      wget -qO- --timeout=30 --header="Content-Type: application/json" "$url"
    fi
  fi
}

register_runner() {
  compatibility_json="$(json_array_from_pipe_list "$SA_RUNNER_COMPATIBILITY_ISSUES")"
  host_facts_json="$(printf '{"os":%s,"arch":%s,"persistent":%s}' "$(json_quote "$SA_RUNNER_HOST_OS")" "$(json_quote "$SA_RUNNER_HOST_ARCH")" "$SA_RUNNER_PERSISTENT")"
  capabilities_json="$(printf '{"transport":"shell-bundle","executor":"local-shell","http_tool":%s}' "$(json_quote "$SA_RUNNER_HTTP_TOOL")")"
  payload="$(printf '{"registration_token":%s,"asset_id":%s,"version":%s,"runtime_kind":%s,"install_mode":%s,"service_mode":%s,"host_facts":%s,"compatibility_issues":%s,"capabilities":%s}' "$(json_quote "$SA_RUNNER_REGISTRATION_TOKEN")" "$(json_quote "${SA_RUNNER_ASSET_ID:-}")" "$(json_quote "$SA_RUNNER_VERSION")" "$(json_quote "$SA_RUNNER_RUNTIME_KIND")" "$(json_quote "$SA_RUNNER_INSTALL_MODE")" "$(json_quote "$SA_RUNNER_SERVICE_MODE")" "$host_facts_json" "$compatibility_json" "$capabilities_json")"
  if ! response="$(http_json POST /api/v1/runner/register "$payload")"; then
    echo "Runner 注册失败：无法访问平台注册接口" >&2
    return 1
  fi
  SA_RUNNER_TOKEN="$(json_get_string runner_token "$response")"
  SA_RUNNER_RUNNER_ID="$(json_get_string runner_id "$response")"
  next_poll="$(json_get_number poll_interval_seconds "$response")"
  if [ -n "$next_poll" ]; then
    SA_RUNNER_POLL_INTERVAL_SECONDS="$next_poll"
  fi
  if [ -z "$SA_RUNNER_TOKEN" ]; then
    echo "Runner 注册失败：未收到 runner_token" >&2
    return 1
  fi
  write_state
}

send_heartbeat() {
  status_value="${1:-online}"
  last_error="${2:-}"
  compatibility_json="$(json_array_from_pipe_list "$SA_RUNNER_COMPATIBILITY_ISSUES")"
  host_facts_json="$(printf '{"os":%s,"arch":%s,"persistent":%s}' "$(json_quote "$SA_RUNNER_HOST_OS")" "$(json_quote "$SA_RUNNER_HOST_ARCH")" "$SA_RUNNER_PERSISTENT")"
  capabilities_json="$(printf '{"transport":"shell-bundle","executor":"local-shell","http_tool":%s}' "$(json_quote "$SA_RUNNER_HTTP_TOOL")")"
  payload="$(printf '{"version":%s,"status":%s,"last_error":%s,"runtime_kind":%s,"install_mode":%s,"service_mode":%s,"host_facts":%s,"compatibility_issues":%s,"capabilities":%s}' "$(json_quote "$SA_RUNNER_VERSION")" "$(json_quote "$status_value")" "$(json_string_or_null "$last_error")" "$(json_quote "$SA_RUNNER_RUNTIME_KIND")" "$(json_quote "$SA_RUNNER_INSTALL_MODE")" "$(json_quote "$SA_RUNNER_SERVICE_MODE")" "$host_facts_json" "$compatibility_json" "$capabilities_json")"
  if ! http_json POST /api/v1/runner/heartbeat "$payload" >/dev/null; then
    return 1
  fi
}

run_assignment_script() {
  encoded_script="$1"
  tmp_script="$(mktemp "${STATE_PATH}.task.XXXXXX")"
  decode_b64 "$encoded_script" >"$tmp_script"
  chmod 0700 "$tmp_script"
  if ! SA_RUNNER_PLATFORM_URL="$SA_RUNNER_PLATFORM_URL" SA_RUNNER_TOKEN="$SA_RUNNER_TOKEN" SA_RUNNER_HTTP_TOOL="$SA_RUNNER_HTTP_TOOL" /bin/sh "$tmp_script"; then
    rm -f "$tmp_script"
    return 1
  fi
  rm -f "$tmp_script"
}

poll_once() {
  if ! response="$(http_json POST /api/v1/runner/poll '{"max_tasks":1}')"; then
    return 1
  fi
  next_poll="$(json_get_number poll_interval_seconds "$response")"
  if [ -n "$next_poll" ]; then
    SA_RUNNER_POLL_INTERVAL_SECONDS="$next_poll"
    write_state
  fi
  next_task_id="$(json_get_string next_task_id "$response")"
  next_script_b64="$(json_get_string next_execution_script_b64 "$response")"
  if [ -z "$next_task_id" ] || [ -z "$next_script_b64" ]; then
    return 0
  fi
  send_heartbeat "busy" ""
  run_assignment_script "$next_script_b64"
  send_heartbeat "online" ""
}

main() {
  detect_http_tool
  if [ -z "$SA_RUNNER_TOKEN" ]; then
    register_runner
  fi
  while true; do
    if [ -z "$SA_RUNNER_TOKEN" ]; then
      register_runner
    fi
    send_heartbeat "online" ""
    if ! poll_once; then
      send_heartbeat "online" "Runner 任务执行失败，请查看平台任务输出" || true
    fi
    sleep "${SA_RUNNER_POLL_INTERVAL_SECONDS:-10}"
  done
}

main "$@"
