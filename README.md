# 健康数据共享访问网关

本地可运行的 Spring Boot 服务，对外提供 HTTP 接口，用于跨机构读取受保护病历数据。
网关保证 **授权判定、脱敏输出、访问审计** 三者结论一致且可解释。
支持 **授权转授（委托）**：已拿到授权的一方可以把权限的一部分转授给合作机构，
由后者以自己的身份读取数据。全部数据使用内存模拟，不依赖任何外部服务。

## 运行与测试

```bash
mvn test          # 运行全部测试（26 个用例）
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
| 1 | 请求方对该患者是否存在授权或转授记录 | `NO_AUTHORIZATION` |
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

## 授权转授（委托）

持有有效授权的一方可以把权限的一部分转授给另一请求方，被转授方以**自己的身份**读取数据。
转授还可以继续向下转授（多级委托），但受到深度与环约束。

### 创建与撤回转授

```
POST /api/gateway/delegations
POST /api/gateway/delegations/{delegationId}/revoke
```

创建请求示例（`sourceId` 可以是原始授权 ID，也可以是上级转授 ID）：

```json
{
  "delegationId": "DEL-1",
  "sourceId": "AUTH-1",
  "delegatorId": "ORG-A",
  "delegateeId": "ORG-B",
  "purposes": ["TREATMENT"],
  "scopes": ["DIAGNOSIS"],
  "validFrom": "2026-10-06T00:00:00Z",
  "validUntil": "2026-10-16T00:00:00Z",
  "requestedAt": "2026-10-06T00:00:00Z"
}
```

### 转授规则

| 顺序 | 校验项 | 失败时的拒绝原因 |
|------|--------|------------------|
| 1 | 上级来源（原始授权或上级转授）存在 | `NO_AUTHORIZATION` |
| 2 | 上级来源当前有效（含整条链路的级联检查） | `REVOKED` / `EXPIRED` / `DELEGATION_REVOKED` / `DELEGATION_EXPIRED` / `PARENT_AUTHORIZATION_INVALID` |
| 3 | 转授方是上级来源的持有者 | `NO_AUTHORIZATION` |
| 4 | 链路深度 ≤ `MAX_DELEGATION_DEPTH`（3 层，原始授权直接转授为第 1 层） | `DELEGATION_DEPTH_EXCEEDED` |
| 5 | 被转授方不在链路持有者序列中（防环，含自我转授） | `DELEGATION_CYCLE` |
| 6 | 转授目的 ⊆ 来源目的 | `PURPOSE_NOT_COVERED` |
| 7 | 转授范围 ⊆ 来源范围 | `SCOPE_NOT_COVERED` |
| 8 | 转授有效期 ⊆ 来源有效期且未结束 | `DELEGATION_EXCEEDS_PARENT` |

**级联收敛**：原始授权（或任一上级转授）被撤回或过期后，下游转授在判定时同步失效，
不再放行。原始授权失效与转授自身失效给出**可区分**的拒绝原因：

- `PARENT_AUTHORIZATION_INVALID`：链路顶端的原始授权（或上级转授）已失效，级联失效；
- `DELEGATION_REVOKED` / `DELEGATION_EXPIRED`：转授自身被撤回 / 不在有效期。

**幂等**：`delegationId` 是幂等键。同一 `delegationId` 重复（含并发）提交只生成一条
转授关系、一条审计记录，后续提交回放首次审计结论。

**可追溯**：每笔转授记录 `rootAuthorizationId`（链路顶端的原始授权）与完整持有者序列
`holderChain`；被转授方每次访问的审计 `basis` 中都带有
`trace 转授来源: delegation=... root-auth=... chain=...`，可定位权限来自哪条原始授权。

### 适用范围与兼容性

- 被转授方的访问走与直接授权**完全相同**的判定、脱敏、审计、复核流水线；
  直接授权访问的行为与既有安全约束（最小必要、直接标识不出网、审计先行、
  取数前复核、请求幂等）**不受影响**。
- 被转授方看到的替代标识以其自身请求方身份派生：对它自己保持稳定，
  与转授方及其他机构不可相互关联。
- 转授只能收窄（范围/目的/有效期不超出上级来源），不能放大权限。

## 脱敏与标识稳定性语义

- **最小必要**：响应只包含本次授权范围内的临床字段（如 `diagnosis`、`medication`），
  未请求的范围不出现。
- **直接标识不出网**：姓名、证件号、电话、地址（`HealthDataStore.DIRECT_IDENTIFIERS`）
  在任何响应中都被过滤；响应与审计记录中患者仅以**替代标识**出现。
- **标识稳定性**：替代标识 = `HMAC-SHA256(派生密钥(请求方), 患者ID)`。
  - 同一请求方对同一患者：标识**稳定**（确定性计算，多次请求相同）；
  - 不同请求方之间：各自使用由本地随机主密钥派生的独立密钥，标识**不可相互关联**，
    且无法从替代标识反推原始患者 ID。被转授方作为独立请求方，天然满足这两条性质。

## 审计记录内容与验证方法

每次放行与拒绝都写入一条 `AuditRecord`，字段包括：

- 请求要素：`requestId`、`requesterId`、`patientPseudonym`（替代标识，非原始 ID）、
  `purpose`、`scopes`、`requestedAt`；
- 判定结论：`allowed`、`denyReason`；
- 判定依据：`basis`（逐项校验轨迹；转授访问含 `trace 转授来源` 行，
  记录 `delegation` / `root-auth` / `chain`，体现转授权限的来源）；
- 审计时间：`auditedAt`。

转授的创建同样落审计：`requestId` 即 `delegationId`，`purpose` 以 `DELEGATE:` 前缀标记，
`basis` 记录来源、深度与持有者链路。

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
- `DelegationFlowTest`：转授能力 12 例——正常转授读取（脱敏/标识稳定/审计可追溯）、
  越权转授被拒（范围/目的/有效期/非持有者）、原始授权撤回与过期的级联收敛、
  转授自身失效与级联失效的可区分原因、并发访问与转授撤回的一致性、
  深度上限与环状委托被拒、重复（含并发）转授幂等；
  每例日志打印 `[输入]`、`[判定依据]`、`[最终结论]`。
- `ConcurrentRevocationTest`：确定性交错（判定放行后撤回，最终结果必须为 `REVOKED`
  且无数据）与 8 线程并发撤回竞争（响应一致性、审计数量与请求数一致、无重复无改写）。
- `GatewayControllerTest`：HTTP 层放行（200 + 脱敏数据）与拒绝（403 + 可区分原因）。

## 代码结构

```
domain/      AccessRequest / Authorization / Delegation / DelegationRequest
             Decision / DenyReason / AuditRecord
store/       AuthorizationStore（授权，支持原子撤回）
             DelegationStore（转授，按 delegationId 幂等，支持原子撤回）
             AuditLog（追加式审计，按 requestId 幂等）
             HealthDataStore（模拟病历，含直接标识）
service/     AuthorizationService（逐项判定：直接授权 + 转授候选）
             DelegationService（转授创建/撤回：越权、深度、环、幂等）
             DelegationChainValidator（转授链路级联校验）
             PseudonymService（替代标识）
             AuditService（审计，不可用时抛异常）
             GatewayService（编排：幂等→判定→审计→复核→脱敏）
api/         GatewayController（POST /api/gateway/access、
             POST /api/gateway/delegations、
             POST /api/gateway/delegations/{id}/revoke）
```
