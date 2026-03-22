# 运行手册

## 1. 启动
```bash
cd infra
docker compose up --build
```

## 2. 初始化管理员
- 推荐方式：打开 `http://localhost:3000/login`
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
