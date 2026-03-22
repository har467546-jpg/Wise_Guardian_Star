# API Contract (v1)

## Auth
- `GET /api/v1/auth/bootstrap-status`
- `POST /api/v1/auth/bootstrap-admin`
- `POST /api/v1/auth/login`

## Discovery
- `POST /api/v1/discovery/jobs`
- `GET /api/v1/discovery/jobs/{job_id}`

## Assets
- `GET /api/v1/assets`
- `PATCH /api/v1/assets/{asset_id}`

## Collection
- `POST /api/v1/collection/assets/{asset_id}/run`

## Risks
- `GET /api/v1/risks/assets/{asset_id}`

## Reports
- `POST /api/v1/reports/jobs/{job_id}/generate`
- `GET /api/v1/reports/{report_id}`

## Vulnerability Library
- `GET /api/v1/vuln-library/status`
- `GET /api/v1/vuln-library/rules`
- `GET /api/v1/vuln-library/rules/export`
- `POST /api/v1/vuln-library/rules/import`
- `POST /api/v1/vuln-library/rules/batch/status`
- `GET /api/v1/vuln-library/rules/{rule_id}`
- `POST /api/v1/vuln-library/rules`
- `PUT /api/v1/vuln-library/rules/{rule_id}`
- `DELETE /api/v1/vuln-library/rules/{rule_id}`
- `POST /api/v1/vuln-library/index/rebuild`
