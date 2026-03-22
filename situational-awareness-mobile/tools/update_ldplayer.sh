#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_PROPERTIES="$ROOT_DIR/android/local.properties"

MODE="debug"
SKIP_BUILD=0
NO_LAUNCH=0
API_BASE_URL="${API_BASE_URL:-}"
ADB_HOST="${ADB_HOST:-}"
ADB_PORT="${ADB_PORT:-5037}"
DEVICE_ID="${DEVICE_ID:-}"
ADB_BIN="${ADB_PATH:-}"

usage() {
  cat <<'EOF'
用法:
  tools/update_ldplayer.sh [选项]

选项:
  --api-base-url URL   指定 API_BASE_URL
  --adb-host HOST      指定远程 ADB server 主机
  --adb-port PORT      指定远程 ADB server 端口，默认 5037
  --device ID          指定设备 ID，例如 emulator-5554
  --adb PATH           指定 adb 可执行文件路径
  --release            构建 release APK
  --skip-build         跳过构建，直接安装现有 APK
  --no-launch          安装后不自动拉起应用
  --help               显示帮助

环境变量:
  API_BASE_URL
  ADB_HOST
  ADB_PORT
  DEVICE_ID
  ADB_PATH
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-base-url=*)
      API_BASE_URL="${1#*=}"
      shift
      ;;
    --api-base-url)
      API_BASE_URL="${2:-}"
      shift 2
      ;;
    --adb-host=*)
      ADB_HOST="${1#*=}"
      shift
      ;;
    --adb-host)
      ADB_HOST="${2:-}"
      shift 2
      ;;
    --adb-port=*)
      ADB_PORT="${1#*=}"
      shift
      ;;
    --adb-port)
      ADB_PORT="${2:-}"
      shift 2
      ;;
    --device=*)
      DEVICE_ID="${1#*=}"
      shift
      ;;
    --device)
      DEVICE_ID="${2:-}"
      shift 2
      ;;
    --adb=*)
      ADB_BIN="${1#*=}"
      shift
      ;;
    --adb)
      ADB_BIN="${2:-}"
      shift 2
      ;;
    --release)
      MODE="release"
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --no-launch)
      NO_LAUNCH=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "未知参数: $1" >&2
      usage
      exit 1
      ;;
  esac
done

resolve_adb() {
  if [[ -n "$ADB_BIN" && -x "$ADB_BIN" ]]; then
    printf '%s\n' "$ADB_BIN"
    return
  fi

  if command -v adb >/dev/null 2>&1; then
    command -v adb
    return
  fi

  local sdk_dir=""
  if [[ -f "$LOCAL_PROPERTIES" ]]; then
    sdk_dir="$(sed -n 's/^sdk\.dir=//p' "$LOCAL_PROPERTIES" | head -n 1)"
  fi

  if [[ -z "$sdk_dir" && -n "${ANDROID_SDK_ROOT:-}" ]]; then
    sdk_dir="$ANDROID_SDK_ROOT"
  fi

  if [[ -z "$sdk_dir" && -n "${ANDROID_HOME:-}" ]]; then
    sdk_dir="$ANDROID_HOME"
  fi

  if [[ -n "$sdk_dir" && -x "$sdk_dir/platform-tools/adb" ]]; then
    printf '%s\n' "$sdk_dir/platform-tools/adb"
    return
  fi

  if [[ -x "/root/Android/Sdk/platform-tools/adb" ]]; then
    printf '%s\n' "/root/Android/Sdk/platform-tools/adb"
    return
  fi

  echo "未找到 adb，请通过 --adb 指定路径。" >&2
  exit 1
}

ADB_BIN="$(resolve_adb)"

if [[ -z "$API_BASE_URL" ]]; then
  API_BASE_URL="http://10.0.2.2:8000/api/v1"
fi

declare -a ADB_CMD
ADB_CMD=("$ADB_BIN")
if [[ -n "$ADB_HOST" ]]; then
  ADB_CMD+=(-H "$ADB_HOST" -P "$ADB_PORT")
fi

list_devices() {
  "${ADB_CMD[@]}" devices | awk 'NR > 1 && $2 == "device" { print $1 }'
}

pick_device() {
  local devices
  devices="$(list_devices)"
  if [[ -z "$devices" ]]; then
    return 1
  fi

  local first_emulator=""
  first_emulator="$(printf '%s\n' "$devices" | grep -E '^(emulator-|127\.0\.0\.1:|localhost:)' | head -n 1 || true)"
  if [[ -n "$first_emulator" ]]; then
    printf '%s\n' "$first_emulator"
    return 0
  fi

  printf '%s\n' "$devices" | head -n 1
}

if [[ -z "$DEVICE_ID" ]]; then
  if ! DEVICE_ID="$(pick_device)"; then
    echo "当前没有可用 Android 设备。" >&2
    if [[ -n "$ADB_HOST" ]]; then
      echo "已尝试远程 ADB server: $ADB_HOST:$ADB_PORT" >&2
    else
      echo "如果雷电运行在 Windows 宿主机，请加上 --adb-host <宿主机IP> --adb-port 5037。" >&2
    fi
    exit 1
  fi
fi

if [[ -z "${JAVA_HOME:-}" && -d "/usr/lib/jvm/java-21-openjdk-amd64" ]]; then
  export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

APP_ID="com.example.situational_awareness_mobile"
APK_PATH="$ROOT_DIR/build/app/outputs/flutter-apk/app-${MODE}.apk"

echo "设备: $DEVICE_ID"
echo "ADB: $ADB_BIN"
if [[ -n "$ADB_HOST" ]]; then
  echo "ADB Server: $ADB_HOST:$ADB_PORT"
fi
echo "构建模式: $MODE"
echo "API_BASE_URL: $API_BASE_URL"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  (cd "$ROOT_DIR" && CI=true flutter build apk "--$MODE" --dart-define="API_BASE_URL=$API_BASE_URL")
fi

if [[ ! -f "$APK_PATH" ]]; then
  echo "APK 不存在: $APK_PATH" >&2
  exit 1
fi

"${ADB_CMD[@]}" -s "$DEVICE_ID" install -r "$APK_PATH"

if [[ "$NO_LAUNCH" -eq 0 ]]; then
  "${ADB_CMD[@]}" -s "$DEVICE_ID" shell am start -n "$APP_ID/$APP_ID.MainActivity"
fi

echo "更新完成。"
