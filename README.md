# 内网资产态势感知平台项目总览

本仓库包含桌面端平台、后端服务和独立 Flutter 移动端两部分，统一服务于“发现 -> 识别 -> 校验 -> 修复 -> 观测”的内网资产态势感知闭环。

## 项目结构

- `situational-awareness/`
  - 桌面端与平台主工程
  - 包含 `frontend/`、`backend/`、`infra/`、`docs/`
- `situational-awareness-mobile/`
  - 独立 Flutter 移动端工程
  - 面向值班巡检、现场排障、移动查看与轻量操作

## 组成说明

### 1. 桌面端平台

桌面端是主控制台，负责承载完整治理链路，适合资产运营、风险研判、任务排查、规则维护和修复编排等重操作场景。

- 前端：Next.js 15 + React 19 + TypeScript + Ant Design 5
- 后端：FastAPI + SQLAlchemy + Celery + Redis + PostgreSQL
- 能力范围：
  - 总览大屏与平台实时监控
  - 扫描发起台与发现流水线
  - 资产列表、资产详情、SSH 授权与信息采集
  - 风险识别、热点资产、风险态势
  - 修复工作台、Runner 安装、修复会话推进
  - 漏洞库、规则导入导出、索引治理
  - 任务中心、日志中心
  - 玄武站内自治助手

详细说明见：[situational-awareness/README.md](/root/Desktop/Project/situational-awareness/README.md)

### 2. 移动端

移动端不是桌面端的完整复制，而是面向手机场景的“运维分析端”，重点解决离开工位后的快速查看、告警确认、轻量触发和现场联动。

- 技术栈：Flutter + Riverpod + go_router + dio
- 能力范围：
  - 登录 / 初始化管理员
  - 总览、资产、任务、风险、我的
  - 资产详情、任务详情、风险详情、发现任务详情
  - `admin` 可见修复工作台
  - 移动玄武助手入口
  - Android 前台 WebSocket 实时提醒 + 本地通知 + 后台定时同步

详细说明见：[situational-awareness-mobile/README.md](/root/Desktop/Project/situational-awareness-mobile/README.md)

## 桌面端与移动端分工

| 维度 | 桌面端 | 移动端 |
| --- | --- | --- |
| 使用场景 | 日常治理、深度分析、运营编排 | 值班巡检、现场排障、碎片化确认 |
| 主要设备 | PC 浏览器 | Android 手机 / 模拟器 |
| 复杂操作 | 完整支持 | 仅保留高频轻量入口 |
| 规则库治理 | 支持 | 不承载 |
| 漏洞修复编排 | 完整支持 | 仅 `admin` 轻量跟进 |
| 实时提醒 | 页面内可视化与日志联动 | WebSocket + 本地通知 |
| 玄武 | 完整站内自治助手 | 移动端助手入口与会话联动 |

## 联调关系

- 桌面端和移动端默认共用 `situational-awareness/backend` 这套后端
- 桌面端前端通过 Next.js 代理访问 `/api/v1/*`
- 移动端通过 `API_BASE_URL` 直连后端 `http://<host>:8000/api/v1`
- 若桌面端 Docker 已启动，移动端只需连通后端地址即可，不需要额外启动第二套服务

## 快速开始

### 1. 启动桌面端与后端

```bash
cd /root/Desktop/Project/situational-awareness/infra
docker compose up -d --build
```

启动后默认入口：

- 桌面端：http://localhost:3000
- 后端文档：http://localhost:8000/docs
- 健康检查：http://localhost:8000/health

### 2. 运行移动端

```bash
cd /root/Desktop/Project/situational-awareness-mobile
flutter pub get
flutter run --dart-define=API_BASE_URL=http://<宿主机局域网IP>:8000/api/v1
```

说明：

- Android 模拟器同机联调可优先使用 `http://10.0.2.2:8000/api/v1`
- 真机联调必须使用宿主机局域网地址，不能写 `127.0.0.1`

## 推荐阅读顺序

1. 先看本文件，快速理解桌面端和移动端的整体分工
2. 再看桌面端说明：[situational-awareness/README.md](/root/Desktop/Project/situational-awareness/README.md)
3. 最后看移动端说明：[situational-awareness-mobile/README.md](/root/Desktop/Project/situational-awareness-mobile/README.md)

## 相关文档

- 架构说明：[situational-awareness/docs/architecture.md](/root/Desktop/Project/situational-awareness/docs/architecture.md)
- API 契约：[situational-awareness/docs/api-contract.md](/root/Desktop/Project/situational-awareness/docs/api-contract.md)
- 数据库结构：[situational-awareness/docs/database-schema.md](/root/Desktop/Project/situational-awareness/docs/database-schema.md)
- 运行手册：[situational-awareness/docs/runbook.md](/root/Desktop/Project/situational-awareness/docs/runbook.md)
