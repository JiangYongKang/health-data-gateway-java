package com.github.highcumontoa.healthdatagatewayjava.tests;

import com.github.highcumontoa.healthdatagatewayjava.config.SampleDataInitializer;
import com.github.highcumontoa.healthdatagatewayjava.model.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.model.AccessResponse;
import com.github.highcumontoa.healthdatagatewayjava.model.AuditRecord;
import com.github.highcumontoa.healthdatagatewayjava.model.DataScope;
import com.github.highcumontoa.healthdatagatewayjava.model.DecisionReason;
import com.github.highcumontoa.healthdatagatewayjava.model.Purpose;
import com.github.highcumontoa.healthdatagatewayjava.service.AccessGatewayService;
import com.github.highcumontoa.healthdatagatewayjava.store.AuditStore;
import com.github.highcumontoa.healthdatagatewayjava.store.GrantStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发撤回场景：访问线程进行到最终复核前，另一线程撤回授权。
 * 撤回与“复核+写审计”互斥，最终结论必须与撤回后状态一致，且不返回失效数据。
 */
@SpringBootTest
class ConcurrentRevocationTests {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRevocationTests.class);

    @Autowired AccessGatewayService gateway;
    @Autowired GrantStore grantStore;
    @Autowired AuditStore auditStore;
    @Autowired SampleDataInitializer initializer;

    @BeforeEach
    void reset() throws Exception {
        auditStore.reset();
        grantStore.reset();
        gateway.setPreAuditHook(null);
        initializer.run();
    }

    @Test
    void revokeConcurrentlyDuringAccessIsLinearizable() throws Exception {
        CountDownLatch reachedHook = new CountDownLatch(1);
        CountDownLatch releaseRevoke = new CountDownLatch(1);

        // 访问线程在“首次判定通过、最终复核前”暂停，等待撤回线程完成撤回
        gateway.setPreAuditHook(r -> {
            reachedHook.countDown();
            try {
                releaseRevoke.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        AccessRequest request = new AccessRequest("REQ-CONC-1", "ORG-A", "P-1001",
                DataScope.MEDICATIONS, Purpose.TREATMENT);

        CompletableFuture<AccessResponse> accessFuture = CompletableFuture.supplyAsync(
                () -> {
                    log.info("[并发] 访问线程发起 requestId={}", request.requestId());
                    return gateway.access(request);
                });

        assertTrue(reachedHook.await(5, TimeUnit.SECONDS), "访问线程应到达撤回窗口");
        CompletableFuture<Boolean> revokeFuture = CompletableFuture.supplyAsync(() -> {
            log.info("[并发] 撤回线程撤回 G-1001");
            return grantStore.revoke("G-1001");
        });
        // 给撤回线程时间获取锁并完成撤回
        Boolean revoked = revokeFuture.get(5, TimeUnit.SECONDS);
        assertTrue(revoked);
        releaseRevoke.countDown();

        AccessResponse response = accessFuture.get(5, TimeUnit.SECONDS);
        log.info("[并发] 输入: requesterId={}, patientId={}, scope={}, purpose={}",
                request.requesterId(), request.patientId(), request.scope(), request.purpose());
        log.info("[并发] 判定依据: {}", response.basis());
        log.info("[并发] 最终结论: allowed={}, reason={}, dataEmpty={}",
                response.allowed(), response.reason(), response.data().isEmpty());

        assertFalse(response.allowed(), "并发撤回生效后不得放行");
        assertEquals(DecisionReason.REVOKED, response.reason());
        assertTrue(response.data().isEmpty(), "不得返回已失效授权下的数据");
        assertNull(response.pseudonym());

        AuditRecord rec = auditStore.findByRequestId("REQ-CONC-1").orElseThrow();
        assertFalse(rec.allowed());
        assertEquals(DecisionReason.REVOKED, rec.reason());
        assertEquals(1, auditStore.all().size());
    }

    @Test
    void concurrentSameRequestIdProducesSingleAuditRecord() throws Exception {
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        @SuppressWarnings("unchecked")
        CompletableFuture<AccessResponse>[] futures = new CompletableFuture[threads];

        for (int i = 0; i < threads; i++) {
            futures[i] = CompletableFuture.supplyAsync(() -> {
                try {
                    start.await();
                    return gateway.access(new AccessRequest("REQ-CONC-DUP", "ORG-A", "P-1001",
                            DataScope.CONDITIONS, Purpose.TREATMENT));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));

        long created = 0;
        long replayed = 0;
        for (CompletableFuture<AccessResponse> f : futures) {
            AccessResponse r = f.get();
            assertTrue(r.allowed());
            if (r.replayed()) {
                replayed++;
            } else {
                created++;
            }
        }
        log.info("[并发幂等] {} 个并发相同请求：首次={}，重放={}，审计记录数={}",
                threads, created, replayed, auditStore.all().size());
        assertEquals(1, created, "只能有一个请求真正写入审计");
        assertEquals(threads - 1, replayed, "其余全部重放");
        assertEquals(1, auditStore.all().size());
    }
}
