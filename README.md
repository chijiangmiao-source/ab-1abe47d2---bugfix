# 飞行数据链路规则隔离审计

上线隔离规则前，按**优先级顺序**逐条核对报文规则是否被更早规则完全遮蔽，避免看似生效的允许/阻断项从未匹配任何流量。

## 核心语义

- 每条规则是五维空间 **协议 × 源 IPv4 × 目的 IPv4 × 源端口 × 目的端口** 中的一个轴对齐**闭区间盒**（协议轴：TCP=0、UDP=1，"两者"=[0,1]；地址为 uint32；端口 0–65535）。
- 服务将先前规则的并集维护为**不相交盒列表**，对当前规则做**精确盒差集**得到剩余区域——不抽样地址、不枚举端口、不以 CIDR 字符串重叠替代判定。
- 裁决：
  - `hit`（仍可命中）：返回按 **协议 → 源地址 → 目的地址 → 源端口 → 目的端口** 字典序的**最小报文见证**（TCP 排在 UDP 前）。
  - `shadowed`（完全遮蔽）：返回 `covered_by` —— 所有与该规则区域相交的更早规则标识（按优先级升序），其并集完全覆盖该规则。
- 结论一经提交即**冻结**：同一审计标识重放相同载荷返回既有结论（HTTP 200，幂等）；**同标识不同载荷**返回 HTTP 409 且不改写既有结论。
- 校验拒绝（HTTP 422，且不留痕）：非法 IPv4 CIDR（含主机位非 0、非法前缀、IPv6）、端口区间越界或下界大于上界、规则标识重复、规则数 0 或超过 18、非法审计标识。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康端点，返回 `{"status":"ok"}` |
| POST | `/api/audits` | 提交审计；201 创建 / 200 幂等重放 / 409 标识冲突 / 422 校验失败 |
| GET | `/api/audits/{audit_id}` | 按审计标识复查冻结结论；404 不存在 |
| GET | `/` | 录入与复查页面 |

请求体示例：

```json
{
  "audit_id": "audit-2026-09-29",
  "rules": [
    {"id": "r1", "protocol": "tcp",
     "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
     "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 85}}
  ]
}
```

`protocol` 取值 `tcp` / `udp` / `both`；端口为闭区间；规则至多 18 条，顺序即优先级。

响应体：`{"audit_id", "created_at", "rules": [...], "verdicts": [...]}`，其中 `verdicts[i]` 对应 `rules[i]`：

```json
{"rule_id": "r2", "status": "hit",
 "witness": {"protocol": "tcp", "src_ip": "10.0.0.128", "dst_ip": "192.168.0.0",
             "src_port": 0, "dst_port": 86}}
```
```json
{"rule_id": "r3", "status": "shadowed", "covered_by": ["r1"]}
```

## 运行（Docker）

```bash
docker compose up --build app          # 默认映射宿主机 8080
HOST_PORT=9000 docker compose up --build app   # 配置宿主机访问端口
docker compose ps                      # app 健康检查基于 /healthz
```

打开 `http://localhost:8080/`（或所配端口）录入审计标识与规则、提交并查看逐规则裁决与见证，也可按审计标识复查冻结结论。

## 验证（verify 服务）

`verify` 服务在 `app` 健康后执行：**构建检查**（compileall）→ **代码测试**（pytest：区域代数精确性、引擎裁决、API 生命周期与拒绝路径）→ **HTTP 冒烟**（一条部分遮蔽、一条完全遮蔽、同标识不同载荷的非法重传、非法 CIDR、幂等重放与冻结复查），并以退出码报告结果：

```bash
docker compose up --build --exit-code-from verify verify
echo $?    # 0 = 全部通过
docker compose down
```

## 本地开发

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q                              # 代码测试
uvicorn app.main:app --port 8080       # 起服务
APP_URL=http://127.0.0.1:8080 python -m verify.run   # 完整验证门禁
```

## 说明与限制

- 审计结论保存在服务内存中，进程重启后清空；冻结语义（同标识拒绝改写）在进程生命周期内严格成立。
- 差集运算对典型 CIDR/端口规则开销可忽略；理论上 18 条规则的病态碎裂场景会增大计算量，但结果始终精确。
