# 运行手册

## 1. 启动
默认生产式运行：
```bash
cd infra
docker compose up -d --build
```

显式开发环境：
```bash
cd infra
docker compose --profile dev up -d --build backend-dev worker-dev frontend-dev
```

## 2. 初始化管理员
- 默认生产式入口：打开 `http://localhost:3000/login`
- 开发环境入口：打开 `http://localhost:3001/login`
- 若系统尚未初始化，登录页会自动显示“初始化管理员”表单
- 创建完成后会自动登录前端

也可以继续使用 API：
```bash
curl http://localhost:8000/api/v1/auth/bootstrap-status

curl -X POST http://localhost:8000/api/v1/auth/bootstrap-admin \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","email":"admin@test.local","password":"ChangeMe123!"}'
```

## 3. 登录获取 Token
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ChangeMe123!"}'
```

## 4. 提交发现任务
```bash
curl -X POST http://localhost:8000/api/v1/discovery/jobs \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"cidr":"192.168.1.0/24","label":"lab-scan"}'
```

开发态后端文档地址：`http://localhost:8001/docs`

## 5. 代码升级后的数据库迁移
- 如果本地继续复用旧的 PostgreSQL 数据卷，代码升级后需要显式执行 Alembic 迁移：
```bash
docker exec sa-backend sh -lc 'cd /app && alembic upgrade head'
docker restart sa-backend sa-worker
```
- `create_all()` 只适合兜底建表，不会替代已有库的列升级或索引字段补齐。

## 6. 漏洞情报同步失败排障
推荐顺序：
1. 先检查 `GET /api/v1/vuln-library/status` 返回的 `schema_ready` 和 `schema_error`
2. 如果 `schema_ready=false`，先执行 `alembic upgrade head`
3. 重启 `sa-backend` 与 `sa-worker`
4. 回到漏洞库页面重新点击“同步情报”
5. 若 schema 已就绪但仍失败，再检查容器外网连通性，以及 NVD / CISA KEV / EPSS 上游是否超时
