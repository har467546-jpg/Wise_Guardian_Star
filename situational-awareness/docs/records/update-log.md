# 更新记录

## 文档目的
- 专门记录项目每次功能、修复、验证相关更新。
- 新记录按日期倒序追加，保留变更范围、验证方式和注意事项。

## 记录格式
```text
## YYYY-MM-DD 更新标题
- 变更范围：
- 主要内容：
- 验证：
- 注意事项：
```

## 2026-06-09 Web 暴露面增强
- 变更范围：
  - 后端发现链路、服务指纹持久化、资产详情页展示、相关单元测试。
- 主要内容：
  - 新增 `backend/app/scanner/web_exposure.py`，对 HTTP/HTTPS 服务采集状态码、页面标题、Server、跳转地址、TLS SAN、DNS 地址/CNAME 和 CDN 启发式识别结果。
  - 在 `probe_open_services` 的 NSE 富化后接入 Web 暴露面增强，结果写入 `DiscoveryJob.summary_json` 和 `AssetPort.fingerprint_json.web`。
  - `service_enrichment.to_fingerprint_json` 增加 `web` 字段持久化。
  - 资产详情页开放端口表新增“Web 暴露面”列，展示 HTTP 状态、标题和 CDN 标记。
  - 增加 Web 探测默认配置：连接超时、读取超时、主机并发。
- 验证：
  - 后端相关测试通过：`../.venv/bin/python -m pytest tests/unit/test_web_exposure.py tests/unit/test_service_enrichment.py tests/unit/test_discovery_tasks.py tests/unit/test_discovery_port_config.py tests/unit/test_network_discovery.py tests/unit/test_port_scanner.py tests/unit/test_nmap_nse.py`，共 80 项通过。
  - 前端构建通过：`npm run build`。
  - 额外执行 Python `compileall` 检查相关后端模块。
- 注意事项：
  - `backend/.venv` 的 Python 3.13.9 在当前环境中运行最小 `asyncio.run()` 会异常退出；测试使用项目根 `../.venv` 的 Python 3.13.12。

## 2026-06-09 Web 暴露面增强补充测试
- 变更范围：
  - 对 Web 暴露面新增能力执行回归测试与本地 smoke 测试。
- 主要内容：
  - 重新运行 Web 暴露面、服务富化、发现任务、端口配置、网络发现、端口扫描、NSE 相关单元测试。
  - 运行前端生产构建，确认资产详情页新增“Web 暴露面”列不破坏类型检查和构建。
  - 启动本地 asyncio HTTP 服务，直接调用 `AsyncWebExposureScanner` 验证可采集状态码、标题和 Server。
- 验证：
  - 后端相关测试通过：`../.venv/bin/python -m pytest tests/unit/test_web_exposure.py tests/unit/test_service_enrichment.py tests/unit/test_discovery_tasks.py tests/unit/test_discovery_port_config.py tests/unit/test_network_discovery.py tests/unit/test_port_scanner.py tests/unit/test_nmap_nse.py`，共 80 项通过。
  - 前端构建通过：`npm run build`。
  - Smoke 输出：`{'port': 37179, 'status_code': 200, 'title': 'Smoke Web Exposure', 'server': 'smoke-nginx/1.0'}`。
- 注意事项：
  - Smoke 测试端口由系统临时分配，不是固定端口。
