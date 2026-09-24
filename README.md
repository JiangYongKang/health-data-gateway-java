# 健康数据共享访问网关（Health Data Gateway）

一个**本地可运行、无外部依赖**的健康数据共享访问网关。跨机构读取受保护病历时，网关把
**授权判定、脱敏输出、访问审计**三件事收敛到同一次决策上，保证三者结论一致、可解释、可追溯。
数据使用内存存储模拟（患者病历、授权、审计均在内存），启动时自动装载样例数据。

- 技术栈：Java 21、Spring Boot 3.4.x、Spring Web、JUnit 5
- 构建：Maven（沿用工程既有方式）

---

## 1. 快速开始

```bash
# 运行全部测试
mvn test

# 本地启动（默认 8080 端口）
mvn spring-boot:run
```

启动后样例数据就绪：患者 `P-1001 张三`、`P-1002 李四`，机构 `ORG-A/B/C/D/E/A2` 与授权 `G-1001 ~ G-1007`。

访问接口：

```bash
curl -X POST http://localhost:8080/api/access \
  -H 'Content-Type: application/json' \
  -d '{"requestId":"C1","requesterId":"ORG-A","patientId":"P-1001",
       "scope":"LAB_RESULTS","purpose":"TREATMENT"}'
```

放行返回 `200`，拒绝返回 `403`，请求要素非法返回 `400`。

### HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/access` | 提交一次受保护数据访问 |
| POST | `/api/admin/grants/{grantId}/revoke` | 撤回授权 |
| GET | `/api/admin/audit` | 查询全部审计记录（只追加、按序号有序） |
| POST | `/api/admin/audit/availability?available=false` | 注入“审计环节不可用”故障（用于验证 fail-closed） |

`/api/access` 请求体：

| 字段 | 含义 |
| --- | --- |
| `requestId` | 请求唯一标识，**幂等键**：同一 requestId 重复提交只产生一条审计 |
| `requesterId` | 请求方（机构）标识 |
| `patientId` | 受保护对象（患者）标识 |
| `scope` | 数据范围：`BASIC_PROFILE` / `CONDITIONS` / `MEDICATIONS` / `LAB_RESULTS` |
| `purpose` | 使用目的：`TREATMENT` / `RESEARCH` / `PUBLIC_HEALTH` / `BILLING` |

响应体：`allowed`、`reason`（可区分原因）、`basis`（人类可读判定依据）、
`replayed`（是否命中既有审计的重放）、`auditSeq`、`pseudonym`、`data`（最小必要脱敏数据）。

---

## 2. 授权判定规则

判定器 `AuthzEvaluator` 对每个请求按**固定优先级逐项校验**，命中第一项即给出结论与依据，
保证不同拒绝情形可区分（对应枚举 `DecisionReason`）：

| 顺序 | 校验项 | 拒绝原因 `reason` |
| --- | --- | --- |
| 1 | 请求方对该患者是否存在授权 | `GRANT_NOT_FOUND` |
| 2 | 授权是否已被撤回 | `REVOKED` |
| 3 | 当前时间是否 ≥ 生效时间 `validFrom` | `NOT_YET_VALID` |
| 4 | 当前时间是否 ≤ 失效时间 `validUntil` | `EXPIRED` |
| 5 | 请求 `scope` 是否包含在授权范围集合内（最小必要） | `SCOPE_EXCEEDED` |
| 6 | 请求 `purpose` 是否包含在授权目的集合内 | `PURPOSE_NOT_PERMITTED` |
| — | 全部通过 | `ALLOWED` |

每条结论都带 `basis`，例如：

```
授权[G-1001]数据范围=[BASIC_PROFILE]，不包含请求范围[LAB_RESULTS]，超出最小必要授权
授权[G-1004]已过期：失效时间=2020-12-31T23:59:59Z，当前时间=2026-...
```

**判定时间统一来自可注入的 `Clock` Bean**（`java.time.Clock`），便于测试控制“当前时间”。

### 访问途中被撤回（并发一致性）

放行路径不是“判定一次就返回”，而是：

1. 首次判定；
2. 经过一个撤回窗口（生产中即正常处理耗时；测试用 `preAuditHook` 确定性注入撤回）；
3. 在**按授权ID分配的锁内做最终复核**，复核通过后**原子写审计**；
4. 审计成功落库后才构建并返回脱敏数据。

撤回操作（`GrantStore.revoke`）与“复核+写审计”使用**同一把按 `grantId` 分配的锁**，二者互斥。
因此：

- 撤回在最终复核前生效 → 结果为 `REVOKED`，不返回任何数据，并记录拒绝审计；
- 撤回在审计落库后生效 → 本次访问已在线性一致点之前完成，返回数据；之后的请求一律拒绝。

不存在“复核已撤回、却按放行返回数据”的窗口。

### 幂等

`requestId` 是幂等键。`AuditStore.append` 在同一把锁内“无则写入、有则返回既有记录”，因此：

- 重复提交（含高并发重复提交）**只产生一条审计记录**；
- 重复请求响应中 `replayed=true`、`auditSeq` 与首次一致，放行结论会确定性重建相同数据。

---

## 3. 脱敏与标识稳定性语义

`DataSanitizer` 负责最小必要裁剪与去标识：

- **绝不输出直接标识**：`name`、`nationalId`、`phone`、原始 `patientId` 不会出现在响应中；
- **最小必要**：响应只含被授权 `scope` 对应的字段
  （`BASIC_PROFILE` 仅年龄/性别；`CONDITIONS`/`MEDICATIONS`/`LAB_RESULTS` 各自独立），其余字段不带出；
- 患者仅以**替代标识（伪标识）`PSN-<hex>`** 出现。

伪标识由 `PseudonymService` 用 HMAC-SHA256 生成，语义为：

- **同一请求方 + 同一患者 → 稳定**：密钥域由全局密钥与 `requesterId` 派生，患者标识在该域内做确定性 HMAC，
  同方多次、不同范围访问得到相同伪标识；
- **不同请求方 → 不可关联**：`requesterId` 被纳入密钥材料，同一患者在不同请求方下得到完全不同的伪标识；
  HMAC 单向不可逆，无法由伪标识反推患者，也无法跨机构关联同一自然人；
- 伪标识本身不含任何直接标识信息。全局密钥可用配置 `gateway.pseudonym.secret` 覆盖。

---

## 4. 访问审计

每次访问（**放行与拒绝都一样**）都会写入一条不可变审计记录 `AuditRecord`：

| 字段 | 内容 |
| --- | --- |
| `seq` | 单调递增序号（写入时分配） |
| `timestamp` | 写入时间 |
| `requestId` / `requesterId` / `patientId` | 请求三要素 |
| `scope` / `purpose` | 请求的数据范围与使用目的 |
| `allowed` / `reason` | 判定结论与可区分原因 |
| `decisionBasis` | 判定依据（逐项校验的人类可读说明） |
| `grantId` | 命中的授权（无授权时为空） |
| `replayed` | 是否重放（新写入恒为 false） |

保证：

- **只追加（append-only）**：记录一旦写入，系统不提供任何修改/删除业务入口；`all()` 返回不可变快照；
- **一致性**：响应的 `allowed/reason/basis` 与审计记录内容同源，判定、脱敏、审计结论一致；
- **审计先于数据**：只有审计成功落库后才返回受保护数据；
- **fail-closed**：审计环节不可用时，任何新请求一律拒绝（`AUDIT_UNAVAILABLE`，`auditSeq=-1`），
  **绝不因无法审计而放行**，且该次不产生数据、不落半条记录。

可通过 `POST /api/admin/audit/availability?available=false` 模拟审计故障，再访问观察 403 行为。

---

## 5. 验证方法

```bash
mvn test
```

测试分布（全部位于 `src/test/.../tests`）：

| 测试类 | 覆盖内容 |
| --- | --- |
| `AccessGatewayServiceTests` | 正常读取、超范围、目的不符、无授权、过期、未生效、已撤回、重复提交、审计失败（已授权/本应拒绝两种）、伪标识稳定性与跨方隔离、访问途中撤回、审计只追加有序 |
| `ConcurrentRevocationTests` | 多线程“访问途中撤回”线性一致；16 线程并发同一 requestId 仅一条审计、其余全部重放 |
| `AccessHttpTests` | 对外 HTTP 接口：200/403/400、拒绝原因可区分、撤回、审计查询、幂等、审计 fail-closed |

单元测试日志对每个用例打印三行：**输入 → 判定依据 → 最终结论**，例如：

```
==== 用例[超范围] 输入: requesterId=ORG-B, patientId=P-1001, scope=LAB_RESULTS, purpose=RESEARCH
==== 用例[超范围] 判定依据: 授权[G-1003]数据范围=[BASIC_PROFILE]，不包含请求范围[LAB_RESULTS]...
==== 用例[超范围] 最终结论: allowed=false, reason=SCOPE_EXCEEDED, replayed=false, auditSeq=1, pseudonym=null
```

也可按第 1 节用 `curl` 手工验证：正常读取无直接标识、超范围 403、重复提交 `replayed=true`、
撤回后 `REVOKED`、审计故障 `AUDIT_UNAVAILABLE`，并用 `GET /api/admin/audit` 核对记录。

---

## 6. 代码结构

```
model/    DataScope / Purpose / DecisionReason 枚举；Grant、PatientRecord、
          AccessRequest、AuthzResult、AuditRecord、AccessResponse
store/    GrantStore、PatientStore、AuditStore（内存，线程安全）
service/  AuthzEvaluator（逐项判定）、PseudonymService（HMAC 伪标识）、
          DataSanitizer（脱敏/裁剪）、AccessGatewayService（编排与一致性）
web/      AccessController、AdminController、GlobalExceptionHandler
config/   ClockConfig、SampleDataInitializer（启动样例数据）
```
