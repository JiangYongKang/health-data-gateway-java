# 健康数据共享访问网关

本地可运行的 Spring Boot 服务，对外提供 HTTP 接口，用于跨机构读取受保护病历数据。
网关保证 **授权判定、脱敏输出、访问审计** 三者结论一致且可解释。
全部数据使用内存模拟，不依赖任何外部服务。

## 运行与测试

```bash
mvn test          # 运行全部测试（14 个用例）
mvn spring-boot:run   # 本地启动，端口 8080
```

HTTP 接口：`POST /api/gateway/access`

```json
{
  "requestId": "REQ-1",
  "requesterId": "ORG-A",
  "patientId": "PATIENT-001",
  "purpose": "TREATMENT",
  "scopes": ["DIAGNOSIS"],
  "requestedAt": "2026-09-25T00:00:00Z"
}
```

放行返回 `200` + 脱敏数据与替代标识；拒绝返回 `403` + 可区分的 `denyReason` 与判定依据 `basis`。

## 授权判定规则

`AuthorizationService` 对每条候选授权**逐项校验**，每一步都写入判定依据（`basis`），保证结论可解释：

| 顺序 | 校验项 | 失败时的拒绝原因 |
|------|--------|------------------|
| 1 | 请求方对该患者是否存在授权记录 | `NO_AUTHORIZATION` |
| 2 | 授权是否已被撤回 | `REVOKED` |
| 3 | 当前时刻是否位于有效期 `[validFrom, validUntil)` 内 | `EXPIRED` |
| 4 | 请求目的是否被授权目的集合覆盖 | `PURPOSE_NOT_COVERED` |
| 5 | 请求数据范围是否为授权范围的子集 | `SCOPE_NOT_COVERED` |
| — | 审计环节不可用（安全策略） | `AUDIT_UNAVAILABLE` |

任一请求方-患者组合可有多条授权，任一授权全部通过即放行；全部不满足时按上表归纳出
**可区分**的拒绝原因。判定结论在返回数据**之前**先落审计；审计写入失败时访问被拒绝
（宁可拒绝，绝不放行）。放行后、读取数据前还会**复核一次授权**：若授权在访问过程中被撤回，
最终结果以撤回后的状态为准，不返回已失效授权下的数据。

**幂等**：`requestId` 是幂等键。重复提交同一 `requestId` 直接回放首次审计结论，
不产生第二条审计记录。

## 脱敏与标识稳定性语义

- **最小必要**：响应只包含本次授权范围内的临床字段（如 `diagnosis`、`medication`），
  未请求的范围不出现。
- **直接标识不出网**：姓名、证件号、电话、地址（`HealthDataStore.DIRECT_IDENTIFIERS`）
  在任何响应中都被过滤；响应与审计记录中患者仅以**替代标识**出现。
- **标识稳定性**：替代标识 = `HMAC-SHA256(派生密钥(请求方), 患者ID)`。
  - 同一请求方对同一患者：标识**稳定**（确定性计算，多次请求相同）；
  - 不同请求方之间：各自使用由本地随机主密钥派生的独立密钥，标识**不可相互关联**，
    且无法从替代标识反推原始患者 ID。

## 审计记录内容与验证方法

每次放行与拒绝都写入一条 `AuditRecord`，字段包括：

- 请求要素：`requestId`、`requesterId`、`patientPseudonym`（替代标识，非原始 ID）、
  `purpose`、`scopes`、`requestedAt`；
- 判定结论：`allowed`、`denyReason`；
- 判定依据：`basis`（逐项校验轨迹）；
- 审计时间：`auditedAt`。

**不可篡改**：`AuditLog` 只提供追加与查询，不提供更新/删除接口；同一 `requestId`
重复追加时返回首次写入的记录，已写入记录不会被静默改写。访问过程中发生撤回时，
复核结论以独立的 `requestId#recheck` 记录**追加**，首条记录保持原样。

**验证方法**：

```bash
mvn test
```

- `GatewayServiceTest`：正常读取、超范围、目的不符、过期、已撤回、无授权、
  重复提交幂等、审计失败拒绝、替代标识稳定性/不可关联性，共 9 例；
  每例日志打印 `[输入]`、`[判定依据]`、`[最终结论]`。
- `ConcurrentRevocationTest`：确定性交错（判定放行后撤回，最终结果必须为 `REVOKED`
  且无数据）与 8 线程并发撤回竞争（响应一致性、审计数量与请求数一致、无重复无改写）。
- `GatewayControllerTest`：HTTP 层放行（200 + 脱敏数据）与拒绝（403 + 可区分原因）。

## 代码结构

```
domain/      AccessRequest / Authorization / Decision / DenyReason / AuditRecord
store/       AuthorizationStore（授权，支持原子撤回）
             AuditLog（追加式审计，按 requestId 幂等）
             HealthDataStore（模拟病历，含直接标识）
service/     AuthorizationService（逐项判定）
             PseudonymService（替代标识）
             AuditService（审计，不可用时抛异常）
             GatewayService（编排：幂等→判定→审计→复核→脱敏）
api/         GatewayController（POST /api/gateway/access）
```
