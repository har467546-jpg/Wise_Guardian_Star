# 运行手册

## 文档目的与适用读者
- 面向本地开发、联调验收与日常运维协作。
- 重点说明启动、初始化、配置、迁移、日志与常见排障入口。

## 当前实现范围
- 默认运行方式基于 Docker Compose。
- 同时提供默认生产式运行与显式开发模式。

## 启动与访问

### 默认生产式运行
```bash
cd infra
docker compose up -d --build
```

访问入口：
- 前端：`http://localhost:3000`
- 后端文档：`http://localhost:8000/docs`
- PostgreSQL：`localhost:5433`
- Redis：`localhost:6380`

### 显式开发模式
```bash
cd infra
docker compose --profile dev up -d --build backend-dev worker-dev frontend-dev
```

访问入口：
- 前端：`http://localhost:3001`
- 后端文档：`http://localhost:8001/docs`

## 初始化与登录

### 初始化管理员
- 默认生产式登录页：`http://localhost:3000/login`
- 开发模式登录页：`http://localhost:3001/login`
- 系统未初始化时，登录页会自动切换到“初始化管理员”表单。

### API 方式初始化
```bash
curl http://localhost:8000/api/v1/auth/bootstrap-status

curl -X POST http://localhost:8000/api/v1/auth/bootstrap-admin \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","email":"admin@test.local","password":"ChangeMe123!"}'
```

### 登录获取 Token
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ChangeMe123!"}'
```

## 常用运行命令
- 查看容器状态：
```bash
cd infra
docker compose ps
```
- 查看后端日志：
```bash
docker logs -f sa-backend
```
- 查看 worker 日志：
```bash
docker logs -f sa-worker
```
- 查看开发态后端日志：
```bash
docker logs -f sa-backend-dev
```
- 查看开发态前端日志：
```bash
docker logs -f sa-frontend-dev
```
- 停止并移除容器：
```bash
cd infra
docker compose down
```

## 常见操作

### 提交发现任务
```bash
curl -X POST http://localhost:8000/api/v1/discovery/jobs \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"cidr":"192.168.1.0/24","label":"lab-scan"}'
```

### 数据库迁移
- 若继续复用已有 PostgreSQL 数据卷，代码升级后需要显式执行 Alembic 迁移：
```bash
docker exec sa-backend sh -lc 'cd /app && alembic upgrade head'
docker restart sa-backend sa-worker
```
- `create_all()` 只做兜底建表，不替代已有库的列升级和索引迁移。

## 配置入口
- 后端模板配置：`backend/.env.example`
- 后端运行时覆盖：`backend/.env.runtime`
- 前端模板配置：`frontend/.env.example`
- 关键运行参数由平台设置页和 `platform_settings_service` 管理。

## 常见排障

### 1. 后端健康检查失败
```bash
curl -s http://localhost:8000/health
```
预期返回：
```json
{"status":"ok"}
```

### 2. 漏洞情报同步失败
推荐顺序：
1. 检查 `GET /api/v1/vuln-library/status` 返回的 `schema_ready` 与 `schema_error`
2. 若 schema 未就绪，执行 `alembic upgrade head`
3. 重启 `sa-backend` 与 `sa-worker`
4. 回到漏洞库页面重新触发同步
5. 若 schema 已就绪仍失败，再检查容器外网连通性及上游超时

### 3. 前端无法连接 API
- 检查后端容器是否正常启动
- 检查 `frontend/.env.example` 中 `BACKEND_INTERNAL_URL`
- 检查浏览器访问地址是否匹配后端 CORS 配置

### 4. 真实局域网扫描不生效
- 默认 Docker `bridge` 网络只适合演示和基础联调
- 真实网段验收应在可见目标网段的宿主机或扫描节点上执行
- 如需稳定排除平台自身，请显式配置 `LOCAL_ASSET_IPS`

## 关键代码入口
- `infra/docker-compose.yml`
- `backend/app/main.py`
- `backend/app/core/config.py`
- `backend/app/services/platform_settings_service.py`
- `backend/app/services/platform_log_service.py`

## 相关文档
- 项目总入口：[../README.md](../README.md)
- 文档总索引：[README.md](README.md)
- 接口说明：[api-contract.md](api-contract.md)
- 测试与验收：[testing-and-acceptance.md](testing-and-acceptance.md)
- 风险联调记录：[records/risk-integration-validation.md](records/risk-integration-validation.md)
