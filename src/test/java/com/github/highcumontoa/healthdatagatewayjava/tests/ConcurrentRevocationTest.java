package com.github.highcumontoa.healthdatagatewayjava.tests;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.service.AuditService;
import com.github.highcumontoa.healthdatagatewayjava.service.AuthorizationService;
import com.github.highcumontoa.healthdatagatewayjava.service.GatewayService;
import com.github.highcumontoa.healthdatagatewayjava.service.PseudonymService;
import com.github.highcumontoa.healthdatagatewayjava.store.AuditLog;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
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
 * 并发撤回场景：
 * 1. 确定性交错——撤回发生在“判定放行之后、读取数据之前”，最终结果必须与撤回后状态一致；
 * 2. 多线程竞争——读取与撤回并发进行，任何响应都不得返回已失效授权下的数据，
 *    且审计记录数与请求数一致、无重复、无改写。
 */
class ConcurrentRevocationTest {

    private static final Instant NOW = Instant.now();

    private AuthorizationStore newStoreWithValidAuth() {
        AuthorizationStore store = new AuthorizationStore();
        store.save(new Authorization(
                "AUTH-RACE", "ORG-A", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                NOW.minus(1, ChronoUnit.DAYS), NOW.plus(30, ChronoUnit.DAYS), false));
        return store;
    }

    private AccessRequest request(String id) {
        return new AccessRequest(id, "ORG-A", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"), Instant.now());
    }

    @Test
    void revocationBetweenDecisionAndRead_finalResultConsistentWithRevokedState() {
        AuthorizationStore store = newStoreWithValidAuth();
        AuditLog auditLog = new AuditLog();

        // 包装判定服务：第一次判定放行后，先撤回授权，再执行取数前复核
        AuthorizationService revokingService = new AuthorizationService(store) {
            private final AtomicInteger calls = new AtomicInteger();

            @Override
            public com.github.highcumontoa.healthdatagatewayjava.domain.Decision evaluate(AccessRequest request) {
                if (calls.incrementAndGet() == 2) {
                    // 模拟“访问过程中授权被撤回”：复核前撤回
                    store.revoke("AUTH-RACE");
                }
                return super.evaluate(request);
            }
        };
        GatewayService gateway = new GatewayService(revokingService,
                new AuditService(auditLog), new PseudonymService(), new HealthDataStore());

        AccessRequest req = request("REQ-RACE-1");
        GatewayService.GatewayResponse resp = gateway.handle(req);

        System.out.println("==== 访问过程中撤回（确定性交错） ====");
        System.out.println("[输入] " + req + " （判定放行后、读取数据前撤回 AUTH-RACE）");
        System.out.println("[判定依据]");
        resp.decision().basis().forEach(b -> System.out.println("  - " + b));
        System.out.println("[最终结论] allowed=" + resp.decision().allowed()
                + " reason=" + resp.decision().denyReason() + " data=" + resp.data());

        // 最终结果必须与撤回后状态一致：拒绝且不得返回数据
        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.REVOKED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());

        // 首条放行审计记录不得被改写；复核结论以独立记录追加
        var first = auditLog.findByRequestId("REQ-RACE-1").orElseThrow();
        assertTrue(first.allowed(), "已写入的放行记录不得被静默改写");
        var recheck = auditLog.findByRequestId("REQ-RACE-1#recheck").orElseThrow();
        assertFalse(recheck.allowed());
        assertEquals(DenyReason.REVOKED, recheck.denyReason());
        assertEquals(2, auditLog.findAll().size());
    }

    @Test
    void concurrentReadsAndRevocation_noDataServedAfterRevocation() throws InterruptedException {
        AuthorizationStore store = newStoreWithValidAuth();
        AuditLog auditLog = new AuditLog();
        GatewayService gateway = new GatewayService(new AuthorizationService(store),
                new AuditService(auditLog), new PseudonymService(), new HealthDataStore());

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
                                gateway.handle(request("REQ-C-" + tid + "-" + i));
                        responses.add(resp);
                        // 一致性：响应要么放行且有数据，要么拒绝且无数据
                        if (resp.decision().allowed() == resp.data().isEmpty()) {
                            violations.add("不一致响应: allowed=" + resp.decision().allowed()
                                    + " data=" + resp.data());
                        }
                        // 拒绝原因必须可区分（撤回后只能以 REVOKED 拒绝）
                        if (!resp.decision().allowed()
                                && resp.decision().denyReason() != DenyReason.REVOKED) {
                            violations.add("撤回后出现非 REVOKED 拒绝: " + resp.decision().denyReason());
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        // 撤回线程：开始后不久撤回授权
        pool.submit(() -> {
            try {
                start.await();
                Thread.sleep(5);
                store.revoke("AUTH-RACE");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        long allowed = responses.stream().filter(r -> r.decision().allowed()).count();
        long denied = responses.size() - allowed;
        System.out.println("==== 并发撤回（" + threads + " 线程 x " + requestsPerThread + " 请求） ====");
        System.out.println("[输入] 并发读取 PATIENT-001，撤回线程中途撤回 AUTH-RACE");
        System.out.println("[最终结论] 总响应=" + responses.size()
                + " 放行=" + allowed + " 拒绝=" + denied
                + " 一致性违规=" + violations.size());
        responses.stream().filter(r -> !r.decision().allowed()).findFirst().ifPresent(r -> {
            System.out.println("[拒绝样例判定依据]");
            r.decision().basis().forEach(b -> System.out.println("  - " + b));
        });

        assertEquals(threads * requestsPerThread, responses.size());
        assertTrue(violations.isEmpty(), "存在不一致响应: " + violations);
        assertTrue(allowed > 0, "撤回前应有部分请求被放行");
        assertTrue(denied > 0, "撤回后应有部分请求被拒绝");

        // 审计完整性：每个 requestId 恰好一条审计记录，放行/拒绝与响应结论一致
        long auditCount = auditLog.findAll().stream()
                .filter(r -> !r.requestId().endsWith("#recheck")).count();
        assertEquals(threads * requestsPerThread, auditCount);
        for (var record : auditLog.findAll()) {
            if (record.requestId().endsWith("#recheck")) {
                assertFalse(record.allowed(), "复核记录只能是拒绝");
            }
        }
    }
}
