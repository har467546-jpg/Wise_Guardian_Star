# situational-awareness-mobile

独立 Flutter 移动端工程，定位为“运维分析端”，面向 `admin / analyst` 的日常查看与轻量操作。当前默认接入 `/root/Desktop/Project/situational-awareness` 这套后端；移动端首版明确不包含流量感知模块，也不试图替代桌面端的完整治理能力。

## 当前范围

- 登录 / 初始化管理员
- 总览
- 资产列表与资产详情
- 资产详情中的修复概览、Runner 状态与安装入口
- `admin` 专属修复工作台：修复资产列表、会话恢复/创建、AI 解读、阶段审批、Runner 安装、任务输出观察
- 任务列表与任务详情
- 任务详情中的事件时间线与执行观测信息
- 全局风险列表与风险详情
- 发现任务创建、列表、详情
- 我的页、主题切换、退出登录

## 移动端用处

这个移动端不是为了把桌面端原样搬到手机上，而是为了在离开工位、值班巡检、现场排障时，提供一个可随手打开的轻量操作入口。

- 快速查看全局态势：资产总量、在线资产、高危风险、活跃任务
- 随时下钻详情：查看单资产、单任务、单风险、单发现任务
- 做轻量操作：触发单资产采集、触发风险验证、创建发现任务
- 做碎片化确认：在手机上先判断“有没有异常、需不需要回到桌面端继续处理”

## 典型场景

- 值班时快速查看当天是否有高危风险或异常任务
- 在机房、实验室、教室等现场环境里查看某台资产的端口、服务和风险情况
- 收到告警后先用手机确认影响范围，再决定是否回到桌面端做进一步治理
- 在外出或不方便开电脑时，快速创建发现任务并跟进执行状态

## 不适合承载的工作

- 大批量资产治理
- 复杂筛选、报表导出和长链路分析
- 规则库维护、漏洞库治理
- 流量感知、深度分析和桌面端级别的运营编排

## 技术栈

- Flutter 3.x + Dart 3.x
- Riverpod
- go_router
- dio
- flutter_secure_storage
- shared_preferences
- fl_chart
- freezed + json_serializable

## 工程状态

- 已生成标准 Flutter 原生工程，包含 `android/`、`ios/`、`test/`
- 依赖已完成解析并生成 `pubspec.lock`
- 已完成与 `/root/Desktop/Project/situational-awareness` 后端的真实联调，已验证登录、总览、风险、任务、修复、玄武相关接口
- 已覆盖风险详情独立加载、登录页、响应式布局等页面级测试
- 已完成依赖解析验证：`flutter pub get`
- 当前 `flutter analyze` 已通过且无告警
- 当前 `flutter test` 已通过
- 当前 `flutter build apk --debug` 已通过
- Android 端已支持“前台 WebSocket 实时提醒 + 本地系统通知 + 后台定时同步”方案，不依赖 Google 服务

## 目录

- `lib/core`: 主题、路由、鉴权、存储、网络
- `lib/features`: login、dashboard、assets、tasks、risks、discovery、profile
- `lib/shared`: 通用 widgets、models、utils
- `android`: Android runner 与 Gradle 工程
- `ios`: iOS runner 与 Xcode 工程

## 验收范围

- 本次可用标准按 Android 收口
- `admin` 可见并操作 remediation workbench
- `analyst` 不显示 remediation 入口，也不会请求 remediation API
- iOS 目录保留，但本次不作为交付验收目标

## 本机环境

当前开发机已完成以下安装：

- Flutter `3.41.4`
- Dart `3.11.1`
- Android SDK `36.1.0`
- Android licenses 已接受
说明：

- Flutter 官方不建议以 `root` 运行；当前机器若继续使用 `root`，可用 `CI=true flutter ...` 规避提示干扰
- 当前机器已配置 Flutter 国内镜像，以避免 `pub.dev` / Google 存储下载过慢

## 运行

先进入工程目录：

```bash
cd /root/Desktop/Project/situational-awareness-mobile
```

拉取依赖：

```bash
flutter pub get
```

联调前先确认 `/root/Desktop/Project/situational-awareness` 的 Docker 链路已启动。这个移动端只负责消费接口，不会自动拉起后端服务。

推荐先在后端目录启动并检查健康状态：

```bash
cd /root/Desktop/Project/situational-awareness/infra
docker compose up -d --build
curl http://127.0.0.1:8000/health
```

推荐优先跑 Android。若使用 Android 模拟器并且后端跑在同一台开发机，`API_BASE_URL` 可直接写：

```bash
http://10.0.2.2:8000/api/v1
```

真机或局域网设备联调时，`API_BASE_URL` 必须改成宿主机局域网可访问地址，例如：

```bash
http://192.168.10.131:8000/api/v1
```

直接调试运行：

```bash
flutter run --dart-define=API_BASE_URL=http://<宿主机局域网IP>:8000/api/v1
```

说明：

- 不要把真机或模拟器的 `API_BASE_URL` 写成 `127.0.0.1`，那只代表设备自身
- Android 模拟器同机联调可优先使用 `10.0.2.2`
- 真机仍应使用宿主机局域网地址
- 后端地址应直接写到 `/api/v1`，例如 `http://192.168.10.131:8000/api/v1`
- Linux 桌面端构建依赖 `libsecret-1`；当前项目主目标是 Android，桌面联调不是优先路径
- iOS 目录已生成，但 iOS 构建仍需 macOS + Xcode 环境

## 提醒机制

当前移动端的设备异常提醒采用不依赖 Google 服务的方案：

- 前台优先连接后端 WebSocket，收到新增高危 / 严重异常时立即弹出页面内提示
- WebSocket 未连接时，仍会通过前台轮询总览数据兜底发现新增异常
- Android 端使用本地系统通知承接提醒点击跳转
- Android 端通过后台定时同步兜底，最短周期约 `15` 分钟
- 后端依赖现有 Redis 做跨进程事件转发，不需要 Firebase、Google Play services 或 `google-services.json`

这套方案更适合雷电等国内模拟器和普通 Android 设备联调。

## 常用命令

基础检查：

```bash
CI=true flutter analyze
CI=true flutter test
```

调试构建 APK：

```bash
CI=true flutter build apk --debug --dart-define=API_BASE_URL=http://<宿主机局域网IP>:8000/api/v1
```

发布构建：

```bash
CI=true flutter build apk --release --dart-define=API_BASE_URL=http://<宿主机局域网IP>:8000/api/v1
```

如果当前机器以 `root` 身份工作，并且 Gradle 需要显式指定 Java 21，可直接使用：

```bash
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 PATH=/usr/lib/jvm/java-21-openjdk-amd64/bin:$PATH GRADLE_OPTS='-Dorg.gradle.daemon=false -Dorg.gradle.java.home=/usr/lib/jvm/java-21-openjdk-amd64' CI=true flutter build apk --debug --dart-define=API_BASE_URL=http://<宿主机局域网IP>:8000/api/v1
```

## APK 安装

安装到本机可见的 Android 设备：

```bash
adb install -r build/app/outputs/flutter-apk/app-debug.apk
```

如果 Flutter 运行在 Kali / Linux 虚拟机里，而 ADB server 在 Windows 宿主机上对外监听，可按当前环境这样安装到雷电或已连接设备：

```bash
/root/Android/Sdk/platform-tools/adb -H 192.168.130.1 -P 5037 -s emulator-5554 install -r /root/Desktop/Project/situational-awareness-mobile/build/app/outputs/flutter-apk/app-debug.apk
```

安装后可直接拉起应用：

```bash
/root/Android/Sdk/platform-tools/adb -H 192.168.130.1 -P 5037 -s emulator-5554 shell am start -n com.example.situational_awareness_mobile/com.example.situational_awareness_mobile.MainActivity
```

真机安装时，把 `emulator-5554` 替换成 `adb devices` 看到的真实设备 ID 即可。

## 一键更新到雷电

项目已提供一键构建并安装脚本：

```bash
cd /root/Desktop/Project/situational-awareness-mobile
tools/update_ldplayer.sh --api-base-url=http://10.0.2.2:8000/api/v1
```

如果雷电运行在 Windows 宿主机，且当前 Linux 环境需要走宿主机 ADB server，可这样执行：

```bash
cd /root/Desktop/Project/situational-awareness-mobile
tools/update_ldplayer.sh --adb-host 192.168.130.1 --adb-port 5037 --device emulator-5554 --api-base-url=http://<宿主机可访问后端IP>:8000/api/v1
```

常用参数：

- `--release`：构建并安装 release APK
- `--skip-build`：跳过构建，直接安装上一次 APK
- `--no-launch`：安装后不自动启动应用
- `--device <id>`：手工指定设备 ID

## 简化入口

如果你只想传“雷电 IP:端口”和“后端 IP:端口”，可以直接用根目录下的 `Package_apk`：

```bash
cd /root/Desktop/Project/situational-awareness-mobile
./Package_apk 192.168.130.1:5555 192.168.130.137:8000
```

它会自动做这些事：

- 把后端地址补成 `http://<后端IP:端口>/api/v1`
- 自动执行 `adb connect <雷电IP:端口>`
- 调用现有 `tools/update_ldplayer.sh` 完成构建、安装和启动

可选参数：

- `--release`：构建并安装 release APK
- `--skip-build`：跳过构建，直接安装已有 APK
- `--no-launch`：安装后不自动启动
- `--adb /path/to/adb`：手工指定 adb 路径

## 产品说明

- 主题内置 `Light / Dark` 两套 token
- 底部导航固定为 `总览 / 资产 / 任务 / 风险 / 我的`
- `发现任务` 通过首页快捷入口和全局 FAB 进入，不占 Tab
- `修复工作台` 为非 Tab 路由：`/remediation` 与 `/remediation/:assetId`
- 总览中的 remediation 快捷入口与资产详情 remediation 区都只对 `admin` 可见
- 窄屏总览会把 `总量 / 在线 / 高危 / 任务` 4 张指标卡压缩到同一行
- 登录页已按移动端单屏使用场景做过压缩和简化，优先保证直观、可快速进入
- 首版不接入流量感知模块
- 风险详情支持按 `risk_id` 独立加载，列表快照仅用于首屏提速
- 资产详情会展示修复摘要、Runner 在线状态、安装状态和最近会话
- 修复工作台会优先恢复活跃会话；如不存在活跃会话，会自动创建新会话
- 任务详情会展示当前阶段、阶段耗时、事件日志和结果 / 错误上下文
- 产品目标是“高频查看 + 轻量触发”，不是桌面端全量功能平移

## 后续建议

- 增加页面级 widget test 与 API mock 测试
- 在有 macOS 环境时补齐 iOS 真机构建与签名流程
