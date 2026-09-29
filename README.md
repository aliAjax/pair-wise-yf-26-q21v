# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限、访问控制，以及到期处置与法定保全。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

服务地址为 <http://127.0.0.1:8102>，默认数据库 `preservation.db`。测试：

```bash
python3 -m unittest -v
```

演示用户：`owner`、`archivist`、`auditor`、`outsider`。API 使用 `X-User-Id`。文件通过 Base64 提交，单文件上限 10 MiB；这是为了保持示例自包含，生产部署应换成对象存储和流式上传。

## 主要接口

- `POST /api/archives`：创建受限档案。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单和副本状态。
- `POST /api/versions/{id}/copies`：创建独立副本内容。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系；新版本继承源版本的保留期与生效中的版本级保全。
- `GET /api/versions/{id}/lineage`：沿迁移记录回溯来源链路，可按原路径追溯到最早版本。
- `GET /api/archives/{id}/status`：保留期限、版本状态和审计记录。
- `POST /api/archives/{id}/enter-disposal`：保留期到期后把档案移入待处置区（幂等，重复进入按现状返回）。
- `POST /api/archives/{id}/holds`：按整份档案或版本（`version_id` 可空）申请法定保全。
- `POST /api/holds/{id}/release`：解除保全。
- `POST /api/archives/{id}/disposal/start`：启动处置任务，逐副本清退；`simulate_fail_locations` 仅用于演示/测试注入介质故障。
- `POST /api/disposal-tasks/{id}/retry`：重试只处理未完成的副本。
- `GET /api/archives/{id}/disposal`：处置状态、保全记录和逐副本清退结果。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志，审计记录保留十年（`prune_audit` 只清理十年前的记录）。

## 到期处置与法定保全

- 档案状态机：`active → pending_disposal → disposing → disposed`；部分副本清退失败时回到 `pending_disposal` 留在待处置区，失败位置逐条记录在 `disposal_copy_results`。
- 保全生效期间（整份档案或任一版本）副本一律不能删：处置启动和重试都会先检查生效中的保全。
- 并发冲突按“先写入状态的一方生效”处理：处置启动与保全申请在同一 `BEGIN IMMEDIATE` 事务内做条件状态迁移，后到请求返回 409 并携带当前状态，已开始的清退不会覆盖保全。
- 处置中或已处置的档案禁止再写入版本、副本或迁移。
- 旧库升级只加列建表（`disposal_state`、`retention_until` 及处置/保全三表），不要求停机回填；旧版本行保留期为空时读取回退到档案级保留期，可查、可校验、可按原路径追溯。
