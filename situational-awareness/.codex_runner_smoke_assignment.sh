#!/bin/sh
set -eu
TASK_ID=smoke-task
SUMMARY_B64=5Zue6LCD6aqM6K+B
PLATFORM_URL="${SA_RUNNER_PLATFORM_URL:-}"
RUNNER_TOKEN="${SA_RUNNER_TOKEN:-}"
HTTP_TOOL="${SA_RUNNER_HTTP_TOOL:-}"
STEP_TIMEOUT_SECONDS="${SA_RUNNER_STEP_TIMEOUT_SECONDS:-180}"
JSON_PYTHON_BIN=""

decode_b64() {
  value="${1:-}"
  if [ -z "$value" ]; then
    return 0
  fi
  if command -v base64 >/dev/null 2>&1; then
    printf "%s" "$value" | base64 -d 2>/dev/null && return 0
    printf "%s" "$value" | base64 --decode 2>/dev/null && return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    printf "%s" "$value" | openssl base64 -d -A 2>/dev/null && return 0
  fi
  return 1
}

resolve_json_python() {
  if [ -n "$JSON_PYTHON_BIN" ]; then
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    JSON_PYTHON_BIN="$(command -v python3)"
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    JSON_PYTHON_BIN="$(command -v python)"
    return 0
  fi
  return 1
}

json_escape_fallback() {
  printf "%s" "${1:-}" | LC_ALL=C tr -d '\000-\010\013\014\016-\037' | awk 'BEGIN { ORS=""; } {
    gsub(/\\/, "\\\\");
    gsub(/"/, "\\\"");
    gsub(/\011/, "\\t");
    gsub(/\015/, "\\r");
    if (NR > 1) printf "\\n";
    printf "%s", $0;
  }'
}

json_quote() {
  if resolve_json_python; then
    printf "%s" "${1:-}" | "$JSON_PYTHON_BIN" -c 'import json, sys; sys.stdout.write(json.dumps(sys.stdin.read(), ensure_ascii=False))'
    return 0
  fi
  printf '"%s"' "$(json_escape_fallback "${1:-}")"
}

json_string_or_null() {
  if [ -n "${1:-}" ]; then
    json_quote "$1"
  else
    printf 'null'
  fi
}

http_post_json() {
  path="$1"
  body="$2"
  if [ "$HTTP_TOOL" = "curl" ]; then
    curl -fsS --connect-timeout 5 --max-time 30 -X POST -H "Content-Type: application/json" -H "X-Runner-Token: $RUNNER_TOKEN" --data "$body" "${PLATFORM_URL%/}$path"
    return $?
  fi
  wget -qO- --timeout=30 --header="Content-Type: application/json" --header="X-Runner-Token: $RUNNER_TOKEN" --post-data="$body" "${PLATFORM_URL%/}$path"
}

post_events() {
  http_post_json "/api/v1/runner/tasks/$TASK_ID/events" "$1" >/dev/null 2>&1 || true
}

emit_stage() {
  event_type="$1"
  stage_code="$2"
  stage_name="$3"
  message_text="$4"
  progress_value="$5"
  payload_json="$6"
  body=$(printf '{"events":[{"event_type":%s,"stage_code":%s,"stage_name":%s,"message":%s,"progress":%s,"payload_json":%s}]}' "$(json_quote "$event_type")" "$(json_quote "$stage_code")" "$(json_quote "$stage_name")" "$(json_string_or_null "$message_text")" "$progress_value" "$payload_json")
  post_events "$body"
}

emit_stream_line() {
  step_id="$1"
  line_text="$(printf "%s" "${2:-}" | cut -c1-800)"
  payload_json=$(printf '{"step_id":%s,"stream":"stdout","text":%s}' "$(json_quote "$step_id")" "$(json_quote "$line_text")")
  body=$(printf '{"events":[{"event_type":"stream","stage_code":"execute_steps","stage_name":"Runner 执行步骤","message":%s,"payload_json":%s}]}' "$(json_string_or_null "$(printf "%s" "$line_text" | cut -c1-255)")" "$payload_json")
  post_events "$body"
}

append_step_result() {
  if [ -n "$STEP_RESULTS_JSON" ]; then
    STEP_RESULTS_JSON="$STEP_RESULTS_JSON,$1"
  else
    STEP_RESULTS_JSON="$1"
  fi
}

run_command_with_timeout() {
  command_text="$1"
  output_file="$2"
  timeout_seconds="${3:-180}"
  timeout_marker="$(mktemp "${TASK_ID}.timeout.XXXXXX")"
  rm -f "$timeout_marker"
  sh -lc "$command_text" >"$output_file" 2>&1 &
  command_pid="$!"
  (
    sleep "$timeout_seconds"
    if kill -0 "$command_pid" >/dev/null 2>&1; then
      : >"$timeout_marker"
      kill "$command_pid" >/dev/null 2>&1 || true
      sleep 2
      kill -9 "$command_pid" >/dev/null 2>&1 || true
    fi
  ) &
  watcher_pid="$!"
  wait "$command_pid"
  exit_code="$?"
  kill "$watcher_pid" >/dev/null 2>&1 || true
  wait "$watcher_pid" 2>/dev/null || true
  if [ -f "$timeout_marker" ]; then
    rm -f "$timeout_marker"
    return 124
  fi
  rm -f "$timeout_marker"
  return "$exit_code"
}

json_array_from_file_tail() {
  file_path="$1"
  limit="${2:-20}"
  if [ ! -f "$file_path" ]; then
    printf '[]'
    return 0
  fi
  tail_file="$(mktemp)"
  tail -n "$limit" "$file_path" >"$tail_file" 2>/dev/null || cat "$file_path" >"$tail_file" 2>/dev/null || true
  json_items=""
  while IFS= read -r raw_line || [ -n "$raw_line" ]; do
    item="$(json_quote "$raw_line")"
    if [ -n "$json_items" ]; then
      json_items="$json_items,$item"
    else
      json_items="$item"
    fi
  done < "$tail_file"
  rm -f "$tail_file"
  printf '[%s]' "$json_items"
}

build_backup_paths_json() {
  backup_kind="${1:-}"
  encoded_targets="${2:-}"
  if [ -z "$backup_kind" ] || [ -z "$encoded_targets" ]; then
    printf '[]'
    return 0
  fi
  targets_content="$(decode_b64 "$encoded_targets" 2>/dev/null || true)"
  if [ -z "$targets_content" ]; then
    printf '[]'
    return 0
  fi
  old_ifs="$IFS"
  IFS='
'
  json_items=""
  for target in $targets_content; do
    [ -n "$target" ] || continue
    item_value=""
    if [ "$backup_kind" = "file_copy" ] && [ -e "$target" ]; then
      backup_path="${target}.bak.sa.$(date +"%Y%m%d%H%M%S")"
      cp -p "$target" "$backup_path" >/dev/null 2>&1 || cp "$target" "$backup_path" >/dev/null 2>&1 || true
      if [ -e "$backup_path" ]; then
        item_value="$backup_path"
      fi
    elif [ "$backup_kind" = "permission_snapshot" ] && [ -e "$target" ]; then
      stat_value="$(stat -c "%a|%u|%g" "$target" 2>/dev/null || true)"
      if [ -n "$stat_value" ]; then
        item_value="${target}|${stat_value}"
      fi
    fi
    if [ -n "$item_value" ]; then
      item_json="$(json_quote "$item_value")"
      if [ -n "$json_items" ]; then
        json_items="$json_items,$item_json"
      else
        json_items="$item_json"
      fi
    fi
  done
  IFS="$old_ifs"
  printf '[%s]' "$json_items"
}

run_step() {
  index="$1"
  total="$2"
  step_id_b64="$3"
  title_b64="$4"
  execution_state="$5"
  command_b64="$6"
  blocked_reason_b64="$7"
  backup_kind="${8:-}"
  backup_targets_b64="${9:-}"
  step_id="$(decode_b64 "$step_id_b64" 2>/dev/null || true)"
  title="$(decode_b64 "$title_b64" 2>/dev/null || true)"
  command_text="$(decode_b64 "$command_b64" 2>/dev/null || true)"
  blocked_reason="$(decode_b64 "$blocked_reason_b64" 2>/dev/null || true)"
  if [ "$execution_state" = "blocked" ]; then
    result_json=$(printf '{"step_id":%s,"title":%s,"status":"blocked","generated_command":null,"exit_status":null,"backup_paths":[],"output_tail":[],"started_at":null,"finished_at":null,"error":%s}' "$(json_quote "$step_id")" "$(json_quote "$title")" "$(json_string_or_null "$blocked_reason")")
    append_step_result "$result_json"
    return 0
  fi
  EXECUTED_COUNT=$((EXECUTED_COUNT + 1))
  progress_value=$((10 + (index * 70 / total)))
  emit_stage "stage" "execute_steps" "Runner 执行步骤" "$title" "$progress_value" "{}"
  backup_paths_json="$(build_backup_paths_json "$backup_kind" "$backup_targets_b64")"
  output_file="$(mktemp)"
  started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  if run_command_with_timeout "$command_text" "$output_file" "$STEP_TIMEOUT_SECONDS"; then
    step_status="success"
    exit_code="0"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
  else
    step_status="failure"
    exit_code="$?"
    FAILED_COUNT=$((FAILED_COUNT + 1))
    FINAL_STATUS="failure"
  fi
  if [ "$step_status" != "success" ] && [ "$exit_code" = "124" ]; then
    printf "%s
" "步骤执行超时，已在 ${STEP_TIMEOUT_SECONDS}s 后终止" >>"$output_file"
  fi
  line_count="0"
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    emit_stream_line "$step_id" "$line"
    line_count=$((line_count + 1))
    if [ "$line_count" -ge 80 ]; then
      break
    fi
  done < "$output_file"
  finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  error_text=""
  if [ "$step_status" != "success" ]; then
    if [ "$exit_code" = "124" ]; then
      error_text="命令执行超时，已超过 ${STEP_TIMEOUT_SECONDS}s"
    else
      error_text="命令执行失败，退出码 $exit_code"
    fi
  fi
  output_tail_json="$(json_array_from_file_tail "$output_file")"
  result_json=$(printf '{"step_id":%s,"title":%s,"status":%s,"generated_command":%s,"exit_status":%s,"backup_paths":%s,"output_tail":%s,"started_at":%s,"finished_at":%s,"error":%s}' "$(json_quote "$step_id")" "$(json_quote "$title")" "$(json_quote "$step_status")" "$(json_string_or_null "$command_text")" "$exit_code" "$backup_paths_json" "$output_tail_json" "$(json_quote "$started_at")" "$(json_quote "$finished_at")" "$(json_string_or_null "$error_text")")
  append_step_result "$result_json"
  if [ "$step_status" != "success" ]; then
    LAST_FAILURE_TITLE="$title"
    LAST_FAILURE_ERROR="$error_text"
  fi
  rm -f "$output_file"
  if [ "$step_status" != "success" ]; then
    return 1
  fi
  return 0
}

if [ -z "$PLATFORM_URL" ] || [ -z "$RUNNER_TOKEN" ]; then
  exit 91
fi
EXECUTED_COUNT="0"
SUCCESS_COUNT="0"
FAILED_COUNT="0"
FINAL_STATUS="success"
STEP_RESULTS_JSON=""
LAST_FAILURE_TITLE=""
LAST_FAILURE_ERROR=""
summary_text="$(decode_b64 "$SUMMARY_B64" 2>/dev/null || printf "整机修复计划")"
emit_stage "stage" "execute_steps" "Runner 执行步骤" "Host Runner 已开始执行整机修复计划" "10" "$(printf '{"assignment":%s}' "$(json_quote "$summary_text")")"
run_step 1 1 c3RlcC0x UnVubmVyIOWbnuiwg+mqjOivgQ== ready ZWNobyBydW5uZXItY2FsbGJhY2stc21va2UtdGVzdA== '' '' '' || break
if [ -n "$STEP_RESULTS_JSON" ]; then
  STEP_RESULTS_PAYLOAD="[$STEP_RESULTS_JSON]"
else
  STEP_RESULTS_PAYLOAD="[]"
fi
if [ "$FINAL_STATUS" = "success" ]; then
  final_message="Host Runner 已完成整机修复计划"
else
  if [ -n "$LAST_FAILURE_TITLE" ]; then
    final_message="Host Runner 执行失败：$LAST_FAILURE_TITLE"
  else
    final_message="Host Runner 执行失败，请查看任务输出"
  fi
fi
complete_payload=$(printf '{"status":%s,"execution":{"executed_count":%s,"success_count":%s,"failed_count":%s,"execution_boundary":"runner_dispatch"},"backups":{},"step_results":%s,"message":%s}' "$(json_quote "$FINAL_STATUS")" "$EXECUTED_COUNT" "$SUCCESS_COUNT" "$FAILED_COUNT" "$STEP_RESULTS_PAYLOAD" "$(json_quote "$final_message")")
http_post_json "/api/v1/runner/tasks/$TASK_ID/complete" "$complete_payload" >/dev/null
