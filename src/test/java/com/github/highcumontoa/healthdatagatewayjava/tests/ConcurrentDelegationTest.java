package com.github.highcumontoa.healthdatagatewayjava.tests;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.DelegationRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.service.AuditService;
import com.github.highcumontoa.healthdatagatewayjava.service.AuthorizationService;
import com.github.highcumontoa.healthdatagatewayjava.service.ChainLock;
import com.github.highcumontoa.healthdatagatewayjava.service.DelegationService;
import com.github.highcumontoa.healthdatagatewayjava.service.GatewayService;
import com.github.highcumontoa.healthdatagatewayjava.service.PseudonymService;
import com.github.highcumontoa.healthdatagatewayjava.store.AuditLog;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
import com.github.highcumontoa.healthdatagatewayjava.store.DelegationStore;
import com.github.highcumontoa.healthdatagatewayjava.store.HealthDataStore;
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
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 转授链路的并发收敛测试：
 * 1. 确定性交错——第一次判定放行后、取数前复核前级联撤回原始授权，
 *    最终结论必须是原始授权失效（REVOKED），且不得返回数据；
 * 2. 多线程竞争——被转授方并发读取与“原始授权撤回+级联”并发进行，
 *    任何响应都不得在撤回后仍读到数据；放行结论与数据一致，审计数量与请求数一致。
 */
class ConcurrentDelegationTest {

    private static final Instant NOW = Instant.now();

    private static final class Harness {
        AuthorizationStore authStore;
        DelegationStore delegationStore;
        AuditLog auditLog;
        AuditService auditService;
        DelegationService delegationService;
        GatewayService gateway;
    }

    private Harness newHarness() {
        Harness h = new Harness();
        h.authStore = new AuthorizationStore();
        h.delegationStore = new DelegationStore();
        h.auditLog = new AuditLog();
        h.auditService = new AuditService(h.auditLog);
        h.delegationService = new DelegationService(
                h.authStore, h.delegationStore, new ChainLock(), h.auditService);
        h.gateway = new GatewayService(new AuthorizationService(h.authStore),
                h.auditService, new PseudonymService(), new HealthDataStore(), h.delegationService);
        h.authStore.save(new Authorization(
                "AUTH-DR", "ORG-A", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                NOW.minus(1, ChronoUnit.DAYS), NOW.plus(30, ChronoUnit.DAYS), false));
        h.delegationService.createDelegation(new DelegationRequest(
                "DEL-DR", "ORG-A", "ORG-B", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"),
                NOW.minusSeconds(60), NOW.plus(20, ChronoUnit.DAYS), Instant.now()));
        return h;
    }

    private AccessRequest request(String id) {
        return new AccessRequest(id, "ORG-B", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"), Instant.now(), "DEL-DR");
    }

    @Test
    void cascadeRevocationBetweenDecisionAndRead_finalResultConsistent() {
        Harness h = newHarness();

        // 包装转授服务：第 2 次评估（取数前复核）前级联撤回原始授权
        DelegationService instrumented = new DelegationService(
                h.authStore, h.delegationStore, new ChainLock(), h.auditService) {
            private final AtomicInteger calls = new AtomicInteger();

            @Override
            public Decision evaluateDelegatedAccess(AccessRequest request) {
                if (calls.incrementAndGet() == 2) {
                    // 模拟访问过程中原始授权被撤回并级联：应与正在进行的访问互斥
                    super.revokeRootAndCascade("AUTH-DR");
                }
                return super.evaluateDelegatedAccess(request);
            }

            @Override
            public <T> T withChainLock(String rootAuthorizationId, java.util.function.Supplier<T> action) {
                // 保持与生产一致：复核+取数仍走真实链路锁（本实例的锁）
                return super.withChainLock(rootAuthorizationId, action);
            }
        };
        GatewayService gateway = new GatewayService(new AuthorizationService(h.authStore),
                h.auditService, new PseudonymService(), new HealthDataStore(), instrumented);

        AccessRequest req = new AccessRequest("REQ-DRACE-1", "ORG-B", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"), Instant.now(), "DEL-DR");
        GatewayService.GatewayResponse resp = gateway.handle(req);

        System.out.println("==== 转授访问过程中级联撤回（确定性交错） ====");
        System.out.println("[输入] " + req + " （首次判定放行后、复核前撤回 AUTH-DR 并级联）");
        System.out.println("[判定依据]");
        resp.decision().basis().forEach(b -> System.out.println("  - " + b));
        System.out.println("[最终结论] allowed=" + resp.decision().allowed()
                + " reason=" + resp.decision().denyReason() + " data=" + resp.data());

        assertFalse(resp.decision().allowed());
        // 源头原始授权失效：REVOKED（可与 DELEGATION_REVOKED 区分）
        assertEquals(DenyReason.REVOKED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());

        var first = h.auditLog.findByRequestId("REQ-DRACE-1").orElseThrow();
        assertTrue(first.allowed(), "首次放行记录不得被改写");
        var recheck = h.auditLog.findByRequestId("REQ-DRACE-1#recheck").orElseThrow();
        assertFalse(recheck.allowed());
        assertEquals(DenyReason.REVOKED, recheck.denyReason());
        assertEquals("DEL-DR", recheck.delegationId());
        assertEquals("AUTH-DR", recheck.rootAuthorizationId());
    }

    @Test
    void concurrentDelegatedAccessAndCascade_noDataServedAfterRevocation()
            throws InterruptedException {
        Harness h = newHarness();

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
                                h.gateway.handle(request("REQ-DC-" + tid + "-" + i));
                        responses.add(resp);
                        if (resp.decision().allowed() == resp.data().isEmpty()) {
                            violations.add("结论与数据不一致: allowed="
                                    + resp.decision().allowed() + " data=" + resp.data());
                        }
                        if (!resp.decision().allowed()
                                && resp.decision().denyReason() != DenyReason.REVOKED) {
                            violations.add("级联撤回后出现非 REVOKED 拒绝: "
                                    + resp.decision().denyReason());
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        pool.submit(() -> {
            try {
                start.await();
                Thread.sleep(5);
                h.delegationService.revokeRootAndCascade("AUTH-DR");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        long allowed = responses.stream().filter(r -> r.decision().allowed()).count();
        long denied = responses.size() - allowed;
        System.out.println("==== 转授并发访问与级联撤回（" + threads + " 线程 x "
                + requestsPerThread + " 请求） ====");
        System.out.println("[输入] ORG-B 经 DEL-DR 并发读取，中途撤回 AUTH-DR 并级联");
        System.out.println("[最终结论] 总响应=" + responses.size()
                + " 放行=" + allowed + " 拒绝=" + denied
                + " 一致性违规=" + violations.size());
        responses.stream().filter(r -> !r.decision().allowed()).findFirst().ifPresent(r -> {
            System.out.println("[拒绝样例判定依据]");
            r.decision().basis().forEach(b -> System.out.println("  - " + b));
        });

        assertEquals(threads * requestsPerThread, responses.size());
        assertTrue(violations.isEmpty(), "存在违规: " + violations);
        assertTrue(allowed > 0, "撤回前应有部分转授访问被放行");
        assertTrue(denied > 0, "撤回后应有部分转授访问被拒绝");

        // 全部放行响应必须确实带数据；全部拒绝必须无数据
        responses.forEach(r -> {
            if (r.decision().allowed()) {
                assertEquals("2型糖尿病", r.data().get("diagnosis"));
            } else {
                assertTrue(r.data().isEmpty());
            }
        });

        // 审计：每个访问 requestId 恰好一条，且都带转授来源
        long accessAudits = h.auditLog.findAll().stream()
                .filter(a -> !a.requestId().endsWith("#recheck")
                        && !a.requestId().equals("DEL-DR"))
                .count();
        assertEquals(threads * requestsPerThread, accessAudits);
        h.auditLog.findAll().stream()
                .filter(a -> a.requestId().startsWith("REQ-DC-"))
                .forEach(a -> {
                    assertEquals("DEL-DR", a.delegationId());
                    assertEquals("AUTH-DR", a.rootAuthorizationId());
                    assertEquals(1, a.delegationDepth());
                });
    }

    @Test
    void concurrentDuplicateDelegationSubmissions_createSingleRelation()
            throws InterruptedException {
        Harness h = newHarness();
        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicInteger success = new AtomicInteger();
        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    DelegationRequest req = new DelegationRequest(
                            "DEL-CONC-DUP", "ORG-A", "ORG-C", "PATIENT-001",
                            "TREATMENT", Set.of("DIAGNOSIS"),
                            NOW.minusSeconds(30), NOW.plus(10, ChronoUnit.DAYS), Instant.now());
                    if (h.delegationService.createDelegation(req).delegation() != null) {
                        success.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        System.out.println("==== 并发重复转授提交幂等 ====");
        System.out.println("[输入] " + threads + " 线程并发提交同一 delegationId=DEL-CONC-DUP");
        System.out.println("[最终结论] 返回关系数=" + success.get()
                + " 实际关系数=" + h.delegationStore.findByRootAuthorization("AUTH-DR").size()
                + " 授权审计数=" + h.auditLog.findAll().stream()
                .filter(a -> a.requestId().equals("DEL-CONC-DUP")).count());

        assertEquals(threads, success.get(), "重复提交都应成功回放");
        assertEquals(2, h.delegationStore.findByRootAuthorization("AUTH-DR").size(),
                "AUTH-DR 下只有 DEL-DR 与 DEL-CONC-DUP 两条关系");
        assertEquals(1, h.auditLog.findAll().stream()
                .filter(a -> a.requestId().equals("DEL-CONC-DUP")).count(),
                "同一转授只产生一条授权审计");
    }
}
