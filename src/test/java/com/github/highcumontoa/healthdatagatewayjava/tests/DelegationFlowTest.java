package com.github.highcumontoa.healthdatagatewayjava.tests;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.DelegationRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.service.AuditService;
import com.github.highcumontoa.healthdatagatewayjava.service.AuthorizationService;
import com.github.highcumontoa.healthdatagatewayjava.service.DelegationChainValidator;
import com.github.highcumontoa.healthdatagatewayjava.service.DelegationService;
import com.github.highcumontoa.healthdatagatewayjava.service.GatewayService;
import com.github.highcumontoa.healthdatagatewayjava.service.PseudonymService;
import com.github.highcumontoa.healthdatagatewayjava.store.AuditLog;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
import com.github.highcumontoa.healthdatagatewayjava.store.DelegationStore;
import com.github.highcumontoa.healthdatagatewayjava.store.HealthDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 授权转授（委托）测试：
 * 正常转授读取 / 越权转授被拒 / 原始授权失效后的级联收敛 / 并发访问与撤回 /
 * 深度上限与环状委托 / 重复转授幂等。
 * 每个用例打印：输入、判定依据、最终结论。
 */
class DelegationFlowTest {

    private AuthorizationStore authorizationStore;
    private DelegationStore delegationStore;
    private AuditLog auditLog;
    private AuditService auditService;
    private GatewayService gatewayService;
    private DelegationService delegationService;

    private static final Instant NOW = Instant.now();

    @BeforeEach
    void setUp() {
        authorizationStore = new AuthorizationStore();
        delegationStore = new DelegationStore();
        auditLog = new AuditLog();
        auditService = new AuditService(auditLog);
        PseudonymService pseudonymService = new PseudonymService();
        DelegationChainValidator chainValidator =
                new DelegationChainValidator(authorizationStore, delegationStore);
        gatewayService = new GatewayService(
                new AuthorizationService(authorizationStore, delegationStore, chainValidator),
                auditService, pseudonymService, new HealthDataStore());
        delegationService = new DelegationService(
                authorizationStore, delegationStore, chainValidator,
                auditService, pseudonymService);

        // 原始授权：ORG-A 对 PATIENT-001，TREATMENT 目的，DIAGNOSIS+MEDICATION 范围
        authorizationStore.save(new Authorization(
                "AUTH-ROOT", "ORG-A", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS", "MEDICATION"),
                NOW.minus(1, ChronoUnit.DAYS), NOW.plus(30, ChronoUnit.DAYS), false));
    }

    private DelegationRequest delegation(String id, String source, String delegator, String delegatee,
                                         Set<String> purposes, Set<String> scopes,
                                         Instant from, Instant until) {
        return new DelegationRequest(id, source, delegator, delegatee,
                purposes, scopes, from, until, Instant.now());
    }

    /** 标准转授：AUTH-ROOT 的子集（TREATMENT / DIAGNOSIS / 剩余 10 天）。 */
    private DelegationRequest standardDelegation(String id, String source,
                                                 String delegator, String delegatee) {
        return delegation(id, source, delegator, delegatee,
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                NOW.minus(1, ChronoUnit.HOURS), NOW.plus(10, ChronoUnit.DAYS));
    }

    private AccessRequest access(String id, String requester) {
        return new AccessRequest(id, requester, "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"), Instant.now());
    }

    private void printDelegation(String title, DelegationRequest req,
                                 DelegationService.DelegationOutcome outcome) {
        System.out.println("==== " + title + " ====");
        System.out.println("[输入] " + req);
        System.out.println("[判定依据]");
        outcome.decision().basis().forEach(b -> System.out.println("  - " + b));
        System.out.println("[最终结论] allowed=" + outcome.decision().allowed()
                + " reason=" + outcome.decision().denyReason()
                + " delegation=" + outcome.delegation().map(d -> d.delegationId()
                        + " depth=" + d.depth() + " root=" + d.rootAuthorizationId()
                        + " chain=" + d.holderChain()).orElse("无"));
    }

    private void printAccess(String title, AccessRequest req, GatewayService.GatewayResponse resp) {
        System.out.println("==== " + title + " ====");
        System.out.println("[输入] " + req);
        System.out.println("[判定依据]");
        resp.decision().basis().forEach(b -> System.out.println("  - " + b));
        System.out.println("[最终结论] allowed=" + resp.decision().allowed()
                + " reason=" + resp.decision().denyReason()
                + " data=" + resp.data()
                + " pseudonym=" + resp.patientPseudonym());
    }

    @Test
    void delegatedAccess_maskedStablePseudonymAndTraceable() {
        // ORG-A 把 DIAGNOSIS 范围转授给 ORG-B
        DelegationRequest del = standardDelegation("DEL-1", "AUTH-ROOT", "ORG-A", "ORG-B");
        DelegationService.DelegationOutcome outcome = delegationService.delegate(del);
        printDelegation("正常转授 ORG-A -> ORG-B", del, outcome);

        assertTrue(outcome.decision().allowed());
        assertTrue(outcome.delegation().isPresent());
        assertEquals(1, outcome.delegation().get().depth());
        assertEquals("AUTH-ROOT", outcome.delegation().get().rootAuthorizationId());
        // 转授行为本身落审计
        assertTrue(auditLog.findByRequestId("DEL-1").isPresent());

        // 被转授方 ORG-B 以自己的身份读取
        GatewayService.GatewayResponse r1 = gatewayService.handle(access("REQ-DEL-1", "ORG-B"));
        GatewayService.GatewayResponse r2 = gatewayService.handle(access("REQ-DEL-2", "ORG-B"));
        printAccess("被转授方读取-第一次", access("REQ-DEL-1", "ORG-B"), r1);
        printAccess("被转授方读取-第二次", access("REQ-DEL-2", "ORG-B"), r2);

        assertTrue(r1.decision().allowed());
        // 最小必要脱敏：只有 DIAGNOSIS 范围字段，无直接标识
        assertEquals("2型糖尿病", r1.data().get("diagnosis"));
        assertFalse(r1.data().containsKey("medication"));
        for (String key : HealthDataStore.DIRECT_IDENTIFIERS) {
            assertFalse(r1.data().containsKey(key));
        }
        // 替代标识：被转授方视角稳定
        assertEquals(r1.patientPseudonym(), r2.patientPseudonym());
        // 与其他机构不可关联
        GatewayService.GatewayResponse ra = gatewayService.handle(access("REQ-DEL-A", "ORG-A"));
        assertNotEquals(ra.patientPseudonym(), r1.patientPseudonym());
        assertFalse(r1.patientPseudonym().contains("PATIENT-001"));

        // 审计可追溯：访问审计的判定依据记录转授来源（哪条原始授权转出来的）
        var audit = auditLog.findByRequestId("REQ-DEL-1").orElseThrow();
        assertTrue(audit.allowed());
        assertTrue(audit.basis().stream().anyMatch(b ->
                b.contains("root-auth=AUTH-ROOT") && b.contains("delegation=DEL-1")),
                "审计判定依据必须可追溯转授来源: " + audit.basis());
    }

    @Test
    void delegationExceedsParentScope_rejected() {
        DelegationRequest del = delegation("DEL-SCOPE", "AUTH-ROOT", "ORG-A", "ORG-B",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS", "LAB"),
                NOW.minus(1, ChronoUnit.HOURS), NOW.plus(10, ChronoUnit.DAYS));
        DelegationService.DelegationOutcome outcome = delegationService.delegate(del);
        printDelegation("越权转授-范围超出", del, outcome);

        assertFalse(outcome.decision().allowed());
        assertEquals(DenyReason.SCOPE_NOT_COVERED, outcome.decision().denyReason());
        assertTrue(outcome.delegation().isEmpty());
        assertTrue(delegationStore.findById("DEL-SCOPE").isEmpty());
    }

    @Test
    void delegationExceedsParentPurpose_rejected() {
        DelegationRequest del = delegation("DEL-PURPOSE", "AUTH-ROOT", "ORG-A", "ORG-B",
                Set.of("RESEARCH"), Set.of("DIAGNOSIS"),
                NOW.minus(1, ChronoUnit.HOURS), NOW.plus(10, ChronoUnit.DAYS));
        DelegationService.DelegationOutcome outcome = delegationService.delegate(del);
        printDelegation("越权转授-目的超出", del, outcome);

        assertFalse(outcome.decision().allowed());
        assertEquals(DenyReason.PURPOSE_NOT_COVERED, outcome.decision().denyReason());
        assertTrue(delegationStore.findById("DEL-PURPOSE").isEmpty());
    }

    @Test
    void delegationExceedsParentValidity_rejected() {
        DelegationRequest del = delegation("DEL-VALIDITY", "AUTH-ROOT", "ORG-A", "ORG-B",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                NOW.minus(1, ChronoUnit.HOURS), NOW.plus(60, ChronoUnit.DAYS));
        DelegationService.DelegationOutcome outcome = delegationService.delegate(del);
        printDelegation("越权转授-有效期超出", del, outcome);

        assertFalse(outcome.decision().allowed());
        assertEquals(DenyReason.DELEGATION_EXCEEDS_PARENT, outcome.decision().denyReason());
        assertTrue(delegationStore.findById("DEL-VALIDITY").isEmpty());
    }

    @Test
    void delegationByNonHolder_rejected() {
        DelegationRequest del = standardDelegation("DEL-NOTHOLD", "AUTH-ROOT", "ORG-X", "ORG-B");
        DelegationService.DelegationOutcome outcome = delegationService.delegate(del);
        printDelegation("越权转授-转授方不持有来源权限", del, outcome);

        assertFalse(outcome.decision().allowed());
        assertEquals(DenyReason.NO_AUTHORIZATION, outcome.decision().denyReason());
        assertTrue(delegationStore.findById("DEL-NOTHOLD").isEmpty());
    }

    @Test
    void rootAuthorizationRevoked_cascadeInvalidatesDelegation() {
        delegationService.delegate(standardDelegation("DEL-C1", "AUTH-ROOT", "ORG-A", "ORG-B"));
        GatewayService.GatewayResponse before = gatewayService.handle(access("REQ-C1", "ORG-B"));
        assertTrue(before.decision().allowed());

        // 原始授权被撤回 -> 转授级联失效
        authorizationStore.revoke("AUTH-ROOT");
        GatewayService.GatewayResponse after = gatewayService.handle(access("REQ-C2", "ORG-B"));
        printAccess("原始授权撤回后的级联收敛", access("REQ-C2", "ORG-B"), after);

        assertFalse(after.decision().allowed());
        assertEquals(DenyReason.PARENT_AUTHORIZATION_INVALID, after.decision().denyReason());
        assertTrue(after.data().isEmpty());
    }

    @Test
    void rootAuthorizationExpired_cascadeInvalidatesDelegation() {
        authorizationStore.save(new Authorization(
                "AUTH-LIVE", "ORG-A", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                NOW.minus(1, ChronoUnit.HOURS), NOW.plus(10, ChronoUnit.DAYS), false));
        delegationService.delegate(standardDelegation("DEL-C2", "AUTH-LIVE", "ORG-A", "ORG-B"));
        assertTrue(gatewayService.handle(access("REQ-C3", "ORG-B")).decision().allowed());

        // 原始授权到期（以已过期的同名记录模拟时间推进）
        authorizationStore.save(new Authorization(
                "AUTH-LIVE", "ORG-A", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                NOW.minus(1, ChronoUnit.HOURS), NOW.minus(1, ChronoUnit.SECONDS), false));
        GatewayService.GatewayResponse after = gatewayService.handle(access("REQ-C4", "ORG-B"));
        printAccess("原始授权过期后的级联收敛", access("REQ-C4", "ORG-B"), after);

        assertFalse(after.decision().allowed());
        assertEquals(DenyReason.PARENT_AUTHORIZATION_INVALID, after.decision().denyReason());
        assertTrue(after.data().isEmpty());
    }

    @Test
    void delegationItselfInvalid_distinguishableFromParentInvalid() {
        delegationService.delegate(standardDelegation("DEL-R1", "AUTH-ROOT", "ORG-A", "ORG-B"));
        // 转授自身被撤回
        delegationService.revoke("DEL-R1");
        GatewayService.GatewayResponse revoked = gatewayService.handle(access("REQ-R1", "ORG-B"));
        printAccess("转授自身被撤回", access("REQ-R1", "ORG-B"), revoked);
        assertFalse(revoked.decision().allowed());
        assertEquals(DenyReason.DELEGATION_REVOKED, revoked.decision().denyReason());

        // 转授自身不在有效期（生效时间在未来）
        delegationService.delegate(delegation("DEL-R2", "AUTH-ROOT", "ORG-A", "ORG-C",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                NOW.plus(1, ChronoUnit.HOURS), NOW.plus(10, ChronoUnit.DAYS)));
        GatewayService.GatewayResponse notYetValid = gatewayService.handle(access("REQ-R2", "ORG-C"));
        printAccess("转授自身尚未生效", access("REQ-R2", "ORG-C"), notYetValid);
        assertFalse(notYetValid.decision().allowed());
        assertEquals(DenyReason.DELEGATION_EXPIRED, notYetValid.decision().denyReason());

        // 原始授权失效：与上面两种原因可区分
        delegationService.delegate(standardDelegation("DEL-R3", "AUTH-ROOT", "ORG-A", "ORG-D"));
        authorizationStore.revoke("AUTH-ROOT");
        GatewayService.GatewayResponse parentInvalid = gatewayService.handle(access("REQ-R3", "ORG-D"));
        printAccess("原始授权失效（级联）", access("REQ-R3", "ORG-D"), parentInvalid);
        assertFalse(parentInvalid.decision().allowed());
        assertEquals(DenyReason.PARENT_AUTHORIZATION_INVALID, parentInvalid.decision().denyReason());
    }

    @Test
    void concurrentAccessAndDelegationRevocation_consistentWithFinalState() throws InterruptedException {
        delegationService.delegate(standardDelegation("DEL-RACE", "AUTH-ROOT", "ORG-A", "ORG-B"));

        int threads = 8;
        int requestsPerThread = 50;
        List<GatewayService.GatewayResponse> responses = new CopyOnWriteArrayList<>();
        List<String> violations = new CopyOnWriteArrayList<>();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads + 1);

        for (int t = 0; t < threads; t++) {
            final int tid = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < requestsPerThread; i++) {
                        GatewayService.GatewayResponse resp =
                                gatewayService.handle(access("REQ-DR-" + tid + "-" + i, "ORG-B"));
                        responses.add(resp);
                        if (resp.decision().allowed() == resp.data().isEmpty()) {
                            violations.add("不一致响应: allowed=" + resp.decision().allowed()
                                    + " data=" + resp.data());
                        }
                        // 转授被撤回后只能以 DELEGATION_REVOKED 拒绝
                        if (!resp.decision().allowed()
                                && resp.decision().denyReason() != DenyReason.DELEGATION_REVOKED) {
                            violations.add("撤回后出现非 DELEGATION_REVOKED 拒绝: "
                                    + resp.decision().denyReason());
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        // 撤回线程：开始后不久撤回转授
        pool.submit(() -> {
            try {
                start.await();
                Thread.sleep(5);
                delegationService.revoke("DEL-RACE");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        long allowed = responses.stream().filter(r -> r.decision().allowed()).count();
        System.out.println("==== 并发访问与转授撤回（" + threads + " 线程 x " + requestsPerThread + " 请求） ====");
        System.out.println("[输入] ORG-B 并发读取 PATIENT-001，撤回线程中途撤回 DEL-RACE");
        System.out.println("[最终结论] 总响应=" + responses.size()
                + " 放行=" + allowed + " 拒绝=" + (responses.size() - allowed)
                + " 一致性违规=" + violations.size());
        responses.stream().filter(r -> !r.decision().allowed()).findFirst().ifPresent(r -> {
            System.out.println("[拒绝样例判定依据]");
            r.decision().basis().forEach(b -> System.out.println("  - " + b));
        });

        assertEquals(threads * requestsPerThread, responses.size());
        assertTrue(violations.isEmpty(), "存在不一致响应: " + violations);
        assertTrue(allowed > 0, "撤回前应有部分请求被放行");
        assertTrue(responses.size() - allowed > 0, "撤回后应有部分请求被拒绝");

        // 审计完整性：每个 requestId 恰好一条记录
        long auditCount = auditLog.findAll().stream()
                .filter(r -> r.requestId().startsWith("REQ-DR-") && !r.requestId().endsWith("#recheck"))
                .count();
        assertEquals(threads * requestsPerThread, auditCount);
    }

    @Test
    void delegationDepthLimit_exceededRejected() {
        DelegationService.DelegationOutcome l1 = delegationService.delegate(
                standardDelegation("DEL-L1", "AUTH-ROOT", "ORG-A", "ORG-B"));
        printDelegation("第 1 层转授 ORG-A -> ORG-B",
                standardDelegation("DEL-L1", "AUTH-ROOT", "ORG-A", "ORG-B"), l1);
        assertTrue(l1.decision().allowed());

        DelegationService.DelegationOutcome l2 = delegationService.delegate(
                standardDelegation("DEL-L2", "DEL-L1", "ORG-B", "ORG-C"));
        printDelegation("第 2 层转授 ORG-B -> ORG-C",
                standardDelegation("DEL-L2", "DEL-L1", "ORG-B", "ORG-C"), l2);
        assertTrue(l2.decision().allowed());

        DelegationService.DelegationOutcome l3 = delegationService.delegate(
                standardDelegation("DEL-L3", "DEL-L2", "ORG-C", "ORG-D"));
        printDelegation("第 3 层转授 ORG-C -> ORG-D",
                standardDelegation("DEL-L3", "DEL-L2", "ORG-C", "ORG-D"), l3);
        assertTrue(l3.decision().allowed());
        assertEquals(DelegationService.MAX_DELEGATION_DEPTH, l3.delegation().orElseThrow().depth());

        // 第 4 层超过深度上限
        DelegationRequest l4req = standardDelegation("DEL-L4", "DEL-L3", "ORG-D", "ORG-E");
        DelegationService.DelegationOutcome l4 = delegationService.delegate(l4req);
        printDelegation("第 4 层转授 ORG-D -> ORG-E（超限）", l4req, l4);
        assertFalse(l4.decision().allowed());
        assertEquals(DenyReason.DELEGATION_DEPTH_EXCEEDED, l4.decision().denyReason());
        assertTrue(delegationStore.findById("DEL-L4").isEmpty());

        // 第 3 层被转授方仍可正常读取（链路有效）
        GatewayService.GatewayResponse resp = gatewayService.handle(access("REQ-L3", "ORG-D"));
        printAccess("第 3 层被转授方读取", access("REQ-L3", "ORG-D"), resp);
        assertTrue(resp.decision().allowed());
    }

    @Test
    void cyclicDelegation_rejected() {
        delegationService.delegate(standardDelegation("DEL-CY1", "AUTH-ROOT", "ORG-A", "ORG-B"));
        delegationService.delegate(standardDelegation("DEL-CY2", "DEL-CY1", "ORG-B", "ORG-C"));

        // 转回链路中已有的持有者 ORG-A：成环
        DelegationRequest cycle = standardDelegation("DEL-CY3", "DEL-CY2", "ORG-C", "ORG-A");
        DelegationService.DelegationOutcome outcome = delegationService.delegate(cycle);
        printDelegation("环状委托 ORG-C -> ORG-A", cycle, outcome);
        assertFalse(outcome.decision().allowed());
        assertEquals(DenyReason.DELEGATION_CYCLE, outcome.decision().denyReason());
        assertTrue(delegationStore.findById("DEL-CY3").isEmpty());

        // 自己转授给自己：同样成环
        DelegationRequest self = standardDelegation("DEL-CY4", "DEL-CY1", "ORG-B", "ORG-B");
        DelegationService.DelegationOutcome selfOutcome = delegationService.delegate(self);
        printDelegation("自我转授 ORG-B -> ORG-B", self, selfOutcome);
        assertFalse(selfOutcome.decision().allowed());
        assertEquals(DenyReason.DELEGATION_CYCLE, selfOutcome.decision().denyReason());
    }

    @Test
    void duplicateDelegation_idempotentNoDuplicateRecordOrAudit() throws InterruptedException {
        DelegationRequest req = standardDelegation("DEL-DUP", "AUTH-ROOT", "ORG-A", "ORG-B");

        // 顺序重复提交
        DelegationService.DelegationOutcome first = delegationService.delegate(req);
        DelegationService.DelegationOutcome second = delegationService.delegate(req);
        printDelegation("重复转授-第一次", req, first);
        printDelegation("重复转授-第二次", req, second);
        assertTrue(first.decision().allowed());
        assertTrue(second.decision().allowed());
        assertEquals(1, auditLog.findAll().stream()
                .filter(r -> r.requestId().equals("DEL-DUP")).count());

        // 并发重复提交
        int threads = 16;
        List<DelegationService.DelegationOutcome> outcomes = new CopyOnWriteArrayList<>();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    outcomes.add(delegationService.delegate(
                            standardDelegation("DEL-DUP-C", "AUTH-ROOT", "ORG-A", "ORG-B")));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        long allowedCount = outcomes.stream().filter(o -> o.decision().allowed()).count();
        System.out.println("==== 并发重复转授（" + threads + " 线程同一 delegationId） ====");
        System.out.println("[输入] " + threads + " 个并发相同转授请求 DEL-DUP-C");
        System.out.println("[最终结论] 放行=" + allowedCount
                + " 转授记录数=" + (delegationStore.findById("DEL-DUP-C").isPresent() ? 1 : 0)
                + " 审计记录数=" + auditLog.findAll().stream()
                        .filter(r -> r.requestId().equals("DEL-DUP-C")).count());

        // 全部放行（幂等回放），但只生成一条转授关系、一条审计记录
        assertEquals(threads, outcomes.size());
        assertTrue(delegationStore.findById("DEL-DUP-C").isPresent());
        assertEquals(1, auditLog.findAll().stream()
                .filter(r -> r.requestId().equals("DEL-DUP-C")).count());
        // 被转授方基于该转授可正常读取
        assertTrue(gatewayService.handle(access("REQ-DUP-C", "ORG-B")).decision().allowed());
    }
}
