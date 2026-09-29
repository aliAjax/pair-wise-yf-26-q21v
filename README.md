# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限、访问控制、到期处置与法定保全。

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

## 到期处置与法定保全

档案到期后进入待处置区，机构可按整份档案或版本申请保全；保全生效期间副本一律不得删除。处置任务与保全申请并发时由数据库串行化，**先写入状态的一方生效**：处置先启动则任务继续，保全先登记则处置按现状返回；清退循环在删除每个副本前重新校验保全，已开始的清退不会覆盖后到的保全。部分副本清退失败时记录失败位置，重试只处理未完成副本，档案留在待处置区。

- `POST /api/archives/{id}/disposal/enter`：档案进入待处置区。
- `POST /api/archives/{id}/disposal/start`：启动处置任务；若存在生效保全则不启动并返回保全现状。
- `POST /api/archives/{id}/disposal/retry`：重试清退，只处理尚未删除的副本。
- `GET /api/archives/{id}/disposal`：查询处置任务、副本结果与剩余副本。
- `POST /api/archives/{id}/holds`：申请保全（`version_id` 省略或为 `null` 时为整份档案保全，否则为版本保全）。
- `GET /api/archives/{id}/holds`：查询保全列表。
- `POST /api/holds/{id}/release`：解除保全。
- `GET /api/disposal/due`：已过保留期但尚未处置完成的到期清单。
- `POST /api/copies/{id}/simulate-disposal-failure`：演示/测试用，标记副本清退时模拟存储失败。

迁移出的新版本自动继承源版本的保留期、保全关系与来源链路（`migrated_from`），可按原路径追溯。旧库升级时只做增量加列，不要求停机回填，旧数据仍可查、可校验、可处置。所有变更写入审计日志，审计记录保留十年。

## 主要接口

- `POST /api/archives`：创建受限档案。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单、副本状态、生效保全与迁移来源。
- `POST /api/versions/{id}/copies`：创建独立副本内容。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本，继承保全与来源链路。
- `GET /api/archives/{id}/status`：保留期限、版本状态、保全、处置摘要和审计记录。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志。
