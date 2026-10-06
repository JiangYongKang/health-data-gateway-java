# 健康数据共享访问网关

本地可运行的 Spring Boot 服务，对外提供 HTTP 接口，用于跨机构读取受保护病历数据。
网关保证 **授权判定、脱敏输出、访问审计** 三者结论一致且可解释，
并支持 **授权转授（委托）**：持权方可把部分权限转授给合作机构，且转授权限随原始授权
一起收敛。全部数据使用内存模拟，不依赖任何外部服务。

## 运行与测试

```bash
mvn test          # 运行全部测试（33 个用例）
mvn spring-boot:run   # 本地启动，端口 8080
```

HTTP 接口：

- `POST /api/gateway/access`：读取数据（直接授权或凭转授关系）；
- `POST /api/gateway/delegations`：创建一笔授权转授。

读取接口请求体（直接授权时省略 `delegationId`）：

```json
{
  "requestId": "REQ-1",
  "requesterId": "ORG-A",
  "patientId": "PATIENT-001",
  "purpose": "TREATMENT",
  "scopes": ["DIAGNOSIS"],
  "requestedAt": "2026-09-25T00:00:00Z",
  "delegationId": null
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

## 授权转授（委托）

持有有效授权的一方（转授方）可把自己权限的**一部分**转授给另一请求方（被转授方），
由后者**以自己的身份**读取数据。转授由 `DelegationService` 管理，
关系保存在 `DelegationStore`，每条转授都记录 `rootAuthorizationId`（链路源头）、
`parentDelegationId`（直接上游）与 `depth`（原始授权为 0，直接转授为 1）。

### 创建转授时的约束（逐项校验，任一不满足即拒绝）

| 校验项 | 规则 | 失败时的拒绝原因 |
|--------|------|------------------|
| 上游来源 | 转授方必须当前持有可覆盖本次转授的有效原始授权或上游转授 | `DELEGATION_SOURCE_NOT_COVERED` |
| 数据范围 | 转授范围只能**更窄或相同**（须为上游范围子集） | `DELEGATION_SCOPE_EXCEEDED` |
| 使用目的 | 转授目的**不能超出**上游目的集合 | `DELEGATION_PURPOSE_EXCEEDED` |
| 有效时间 | 不得早于上游生效、不得晚于上游失效，即**不得长于原始授权剩余时间** | `DELEGATION_DURATION_EXCEEDED` |
| 链路深度 | 整条链路深度上限 `DelegationService.MAX_DELEGATION_DEPTH = 3` | `DELEGATION_TOO_DEEP` |
| 环路 | 被转授方不得已经出现在链路中（含转授给自己） | `DELEGATION_CYCLE` |
| 审计 | 转授授权事件也必须落审计，审计不可用则拒绝创建 | `AUDIT_UNAVAILABLE` |

### 凭转授访问的判定

访问请求携带 `delegationId` 时，网关沿链路**自叶子向源头逐级校验**：

1. 访问方必须是该转授关系的被转授方、患者一致（否则 `DELEGATION_PARTY_MISMATCH`，
   引用不存在的关系为 `DELEGATION_NOT_FOUND`）；
2. **先校验源头原始授权**：撤回为 `REVOKED`、过期为 `EXPIRED`、缺失为 `NO_AUTHORIZATION`；
3. 再逐级校验每一跳转授：该级撤回为 `DELEGATION_REVOKED`、过期为 `DELEGATION_EXPIRED`，
   目的/范围不符为 `PURPOSE_NOT_COVERED` / `SCOPE_NOT_COVERED`；
4. 全链有效才放行，判定依据 `basis` 中打印完整 `chain-trace`（逐跳机构与关系标识）。

**原始授权失效与转授权限失效给出可区分的原因**：源头失效是 `REVOKED` / `EXPIRED`，
转授关系自身失效是 `DELEGATION_REVOKED` / `DELEGATION_EXPIRED`，便于定位问题。

### 级联收敛与并发一致性

- 原始授权被撤回时，`revokeRootAndCascade` 在**链路锁**内原子撤回该原始授权及其下
  **全部层级**的转授关系；原始授权过期同样使整条链路不可用。
- 同一原始授权链路的「转授创建 / 转授访问判定 / 原始授权撤回 / 级联撤回」由
  `ChainLock`（以根原始授权标识为键的分段锁，不同链路互不阻塞）串行化。
  转授访问的「取数前复核 + 读取数据」在同一把链路锁内完成，因此即使访问与撤回并发交错，
  也不会出现某个请求拿着已失效的转授权限读到数据；最终结论与最新状态一致。
- 撤回单条转授（`revokeDelegation`）只使该跳及其下游失效，不影响上游与原始授权持有人。

### 幂等与去重

`delegationId` 是转授的幂等键：同一笔转授重复提交（含并发提交）只产生**一条**转授关系、
**一条** `DELEGATION_GRANT` 授权审计记录，重复提交回放首次结论。

### 适用范围与兼容性

- 被转授方拿到的数据同样执行**最小必要脱敏**：仅返回该转授范围内的临床字段，
  直接标识一律过滤；替代标识以**被转授方自己的视角**派生，对同一患者稳定、
  与转授方及其他机构之间不可相互关联。
- **不改变直接授权访问的既有行为与安全约束**：请求不带 `delegationId` 时走原有
  `AuthorizationService` 判定路径，原有的逐项校验、审计先行、取数前复核、幂等回放、
  脱敏规则全部保留（既有 14 个测试无回归）。

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
- 判定依据：`basis`（逐项校验轨迹，转授访问含逐跳 `chain-trace`）；
- 转授来源（转授访问时）：`delegationId`（叶子转授）、`rootAuthorizationId`（源头原始授权）、
  `delegationDepth`（链路深度），可据此把每一笔访问追溯到是从哪条原始授权、经哪条转授链转出来的；
- 事件类型：`eventType` 为 `ACCESS`（读取）或 `DELEGATION_GRANT`（转授授权事件）；
  授权事件另记 `delegatorId`（转授方）；
- 审计时间：`auditedAt`。

**不可篡改**：`AuditLog` 只提供追加与查询，不提供更新/删除接口；同一 `requestId`
（转授授权事件用 `delegationId`）重复追加时返回首次写入的记录，已写入记录不会被静默改写。
访问过程中发生撤回时，复核结论以独立的 `requestId#recheck` 记录**追加**，首条记录保持原样。

**验证方法**：

```bash
mvn test
```

- `GatewayServiceTest`：正常读取、超范围、目的不符、过期、已撤回、无授权、
  重复提交幂等、审计失败拒绝、替代标识稳定性/不可关联性，共 9 例；
  每例日志打印 `[输入]`、`[判定依据]`、`[最终结论]`。
- `ConcurrentRevocationTest`：直接授权的确定性交错与 8 线程并发撤回竞争。
- `DelegationServiceTest`（14 例）：正常转授读取（含来源追溯与授权审计）、
  越权转授（范围/目的/有效期/无上游）被拒、深度上限、环状委托、重复转授幂等、
  原始授权撤回级联收敛（`REVOKED`）、转授自身撤回（`DELEGATION_REVOKED`）、
  转授过期（`DELEGATION_EXPIRED`）、被转授方替代标识稳定且跨机构不可关联、
  非被转授方冒用/引用不存在关系；每例同样打印三段式日志。
- `ConcurrentDelegationTest`（3 例）：转授访问「判定放行后级联撤回」确定性交错
  （最终必须 `REVOKED` 且无数据、复核记录带转授来源）、8 线程并发转授访问与级联撤回竞争
  （撤回后绝不返回数据、结论与数据一致、审计数量与请求一致且都带转授来源）、
  并发重复转授提交只产生一条关系与一条授权审计。
- `GatewayControllerTest` / `DelegationControllerTest`：HTTP 层直接访问、转授创建、
  凭转授访问、越权转授 403 的冒烟测试。

## 本地手工验证转授能力

```bash
mvn spring-boot:run
```

```bash
# 1) ORG-A 把 PATIENT-001 的 DIAGNOSIS 范围（TREATMENT 目的）转授给 ORG-B
curl -s -X POST localhost:8080/api/gateway/delegations \
  -H 'Content-Type: application/json' -d '{
    "delegationId":"DEL-DEMO-1","delegatorId":"ORG-A","delegateeId":"ORG-B",
    "patientId":"PATIENT-001","purpose":"TREATMENT","scopes":["DIAGNOSIS"],
    "validFrom":"2026-10-06T00:00:00Z","validUntil":"2026-10-20T00:00:00Z",
    "requestedAt":"2026-10-06T00:00:00Z"}'
# 前提：ORG-A 已持有覆盖该内容的原始授权；越权（如带上 LAB 范围）会返回 403
# 且 denyReason=DELEGATION_SCOPE_EXCEEDED。

# 2) ORG-B 以自己的身份、凭转授关系读取
curl -s -X POST localhost:8080/api/gateway/access \
  -H 'Content-Type: application/json' -d '{
    "requestId":"REQ-DEMO-1","requesterId":"ORG-B","patientId":"PATIENT-001",
    "purpose":"TREATMENT","scopes":["DIAGNOSIS"],"requestedAt":"2026-10-06T00:00:00Z",
    "delegationId":"DEL-DEMO-1"}'
# 放行返回脱敏数据与 ORG-B 视角的替代标识；basis 中可见 chain-trace 与 rootAuthorizationId。
# 重复提交同一 delegationId 的转授申请只回放同一条关系，不产生重复审计。
```

> 注：内存存储中的授权通过 `AuthorizationStore` 预置（测试内构造）；
> 生产化时替换为持久化实现即可，判定与收敛语义不变。

## 代码结构

```
domain/      AccessRequest（含可选 delegationId）/ Authorization /
             Delegation / DelegationRequest / Decision / DenyReason / AuditRecord
store/       AuthorizationStore（授权，支持原子撤回）
             DelegationStore（转授关系，原子撤回/级联查询/幂等保存）
             AuditLog（追加式审计，按 requestId 幂等）
             HealthDataStore（模拟病历，含直接标识）
service/     AuthorizationService（直接授权逐项判定）
             DelegationService（转授创建约束、链路访问判定、级联收敛、深度/环路控制）
             ChainLock（按根原始授权分段的链路锁，保证并发一致）
             PseudonymService（替代标识，以实际访问方视角派生）
             AuditService（访问审计与转授授权审计，不可用时抛异常）
             GatewayService（编排：幂等→直接/转授判定→审计→锁内复核取数→脱敏）
api/         GatewayController（POST /api/gateway/access）
             DelegationController（POST /api/gateway/delegations）
```
