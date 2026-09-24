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

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 访问网关核心单测：授权边界、幂等、审计 fail-closed、脱敏与伪标识稳定性。
 * 每个用例均打印 输入 / 判定依据 / 最终结论。
 */
@SpringBootTest
class AccessGatewayServiceTests {

    private static final Logger log = LoggerFactory.getLogger(AccessGatewayServiceTests.class);

    @Autowired AccessGatewayService gateway;
    @Autowired GrantStore grantStore;
    @Autowired AuditStore auditStore;
    @Autowired SampleDataInitializer initializer;

    @BeforeEach
    void reset() throws Exception {
        auditStore.reset();
        grantStore.reset();
        gateway.setPreAuditHook(null);
        // 重新装载干净的样例数据
        initializer.run();
    }

    private AccessRequest req(String id, String org, String patient, DataScope scope, Purpose purpose) {
        return new AccessRequest(id, org, patient, scope, purpose);
    }

    private void printCase(String title, AccessRequest in, AccessResponse out) {
        log.info("==== 用例[{}] 输入: requesterId={}, patientId={}, scope={}, purpose={}",
                title, in.requesterId(), in.patientId(), in.scope(), in.purpose());
        log.info("==== 用例[{}] 判定依据: {}", title, out.basis());
        log.info("==== 用例[{}] 最终结论: allowed={}, reason={}, replayed={}, auditSeq={}, pseudonym={}",
                title, out.allowed(), out.reason(), out.replayed(), out.auditSeq(), out.pseudonym());
    }

    @Test
    void normalReadAllowedAndSanitized() {
        AccessRequest in = req("REQ-OK-1", "ORG-A", "P-1001", DataScope.LAB_RESULTS, Purpose.TREATMENT);
        AccessResponse out = gateway.access(in);
        printCase("正常读取", in, out);

        assertTrue(out.allowed());
        assertEquals(DecisionReason.ALLOWED, out.reason());
        assertFalse(out.replayed());
        assertTrue(out.auditSeq() > 0);

        // 最小必要：仅含授权范围数据 + 伪标识
        Map<String, Object> data = out.data();
        assertTrue(data.containsKey("labResults"));
        assertFalse(data.containsKey("conditions"));
        assertFalse(data.containsKey("medications"));
        // 不得出现任何直接标识
        String json = data.toString();
        assertFalse(json.contains("张三"));
        assertFalse(json.contains("11010119900101001X"));
        assertFalse(json.contains("138-0000-0001"));
        assertFalse(json.contains("P-1001"));
        assertNotNull(out.pseudonym());
        assertTrue(out.pseudonym().startsWith("PSN-"));

        // 审计已记录且为放行
        AuditRecord rec = auditStore.findByRequestId("REQ-OK-1").orElseThrow();
        assertTrue(rec.allowed());
        assertEquals(DecisionReason.ALLOWED, rec.reason());
    }

    @Test
    void scopeExceeded() {
        AccessRequest in = req("REQ-SCOPE-1", "ORG-B", "P-1001", DataScope.LAB_RESULTS, Purpose.RESEARCH);
        AccessResponse out = gateway.access(in);
        printCase("超范围", in, out);

        assertFalse(out.allowed());
        assertEquals(DecisionReason.SCOPE_EXCEEDED, out.reason());
        assertTrue(out.data().isEmpty());
        AuditRecord rec = auditStore.findByRequestId("REQ-SCOPE-1").orElseThrow();
        assertEquals(DecisionReason.SCOPE_EXCEEDED, rec.reason());
    }

    @Test
    void purposeNotPermitted() {
        AccessRequest in = req("REQ-PURPOSE-1", "ORG-B", "P-1001", DataScope.BASIC_PROFILE, Purpose.TREATMENT);
        AccessResponse out = gateway.access(in);
        printCase("目的不符", in, out);

        assertFalse(out.allowed());
        assertEquals(DecisionReason.PURPOSE_NOT_PERMITTED, out.reason());
    }

    @Test
    void grantNotFound() {
        AccessRequest in = req("REQ-NONE-1", "ORG-X", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT);
        AccessResponse out = gateway.access(in);
        printCase("无授权", in, out);

        assertFalse(out.allowed());
        assertEquals(DecisionReason.GRANT_NOT_FOUND, out.reason());
    }

    @Test
    void expiredGrantRejected() {
        AccessRequest in = req("REQ-EXPIRED-1", "ORG-C", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT);
        AccessResponse out = gateway.access(in);
        printCase("已过期", in, out);

        assertFalse(out.allowed());
        assertEquals(DecisionReason.EXPIRED, out.reason());
    }

    @Test
    void notYetValidGrantRejected() {
        AccessRequest in = req("REQ-FUTURE-1", "ORG-D", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT);
        AccessResponse out = gateway.access(in);
        printCase("未生效", in, out);

        assertFalse(out.allowed());
        assertEquals(DecisionReason.NOT_YET_VALID, out.reason());
    }

    @Test
    void alreadyRevokedGrantRejected() {
        AccessRequest in = req("REQ-REV-1", "ORG-E", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT);
        AccessResponse out = gateway.access(in);
        printCase("已撤回", in, out);

        assertFalse(out.allowed());
        assertEquals(DecisionReason.REVOKED, out.reason());
    }

    @Test
    void duplicateSubmissionProducesSingleAudit() {
        AccessRequest first = req("REQ-DUP-1", "ORG-A", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT);
        AccessResponse r1 = gateway.access(first);
        AccessResponse r2 = gateway.access(first);
        printCase("重复提交-第一次", first, r1);
        printCase("重复提交-第二次", first, r2);

        assertTrue(r1.allowed());
        assertFalse(r1.replayed());
        assertTrue(r2.allowed());
        assertTrue(r2.replayed(), "重复提交必须标记为重放");
        assertEquals(r1.auditSeq(), r2.auditSeq(), "两次必须对应同一条审计记录");
        assertEquals(r1.pseudonym(), r2.pseudonym());

        long count = auditStore.all().stream().filter(r -> r.requestId().equals("REQ-DUP-1")).count();
        assertEquals(1, count, "同一 requestId 只能有一条审计记录");
    }

    @Test
    void auditUnavailableDeniesEvenWhenAuthorized() {
        auditStore.setAvailable(false);
        AccessRequest in = req("REQ-AUDITDOWN-1", "ORG-A", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT);
        AccessResponse out = gateway.access(in);
        printCase("审计故障-已授权", in, out);

        assertFalse(out.allowed());
        assertEquals(DecisionReason.AUDIT_UNAVAILABLE, out.reason());
        assertTrue(out.data().isEmpty());
        assertEquals(0, auditStore.all().size());
    }

    @Test
    void auditUnavailableAlsoDeniesWhenWouldBeRejected() {
        auditStore.setAvailable(false);
        AccessRequest in = req("REQ-AUDITDOWN-2", "ORG-X", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT);
        AccessResponse out = gateway.access(in);
        printCase("审计故障-本应拒绝", in, out);

        assertFalse(out.allowed());
        assertEquals(DecisionReason.AUDIT_UNAVAILABLE, out.reason());
    }

    @Test
    void pseudonymStableForSameRequesterButUnlinkableAcrossRequesters() {
        AccessRequest a1 = req("REQ-PSN-A1", "ORG-A", "P-1002", DataScope.BASIC_PROFILE, Purpose.TREATMENT);
        AccessRequest a2 = req("REQ-PSN-A2", "ORG-A", "P-1002", DataScope.MEDICATIONS, Purpose.TREATMENT);
        AccessRequest b = req("REQ-PSN-B", "ORG-A2", "P-1002", DataScope.BASIC_PROFILE, Purpose.TREATMENT);

        AccessResponse ra1 = gateway.access(a1);
        AccessResponse ra2 = gateway.access(a2);
        AccessResponse rb = gateway.access(b);
        printCase("同请求方第一次", a1, ra1);
        printCase("同请求方第二次", a2, ra2);
        printCase("不同请求方", b, rb);

        assertEquals(ra1.pseudonym(), ra2.pseudonym(), "同一请求方对同一对象的伪标识必须稳定");
        assertNotEquals(ra1.pseudonym(), rb.pseudonym(), "不同请求方的伪标识必须不同、不可关联");
    }

    @Test
    void revokeDuringAccessYieldsRevokedResultAndNoData() {
        // 在首次评估通过后、最终复核前撤回授权
        gateway.setPreAuditHook(r -> {
            log.info(">>> 测试钩子：访问途中撤回授权 G-1001 (requestId={})", r.requestId());
            assertTrue(grantStore.revoke("G-1001"));
        });
        AccessRequest in = req("REQ-RACE-REVOKE-1", "ORG-A", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT);
        AccessResponse out = gateway.access(in);
        printCase("访问途中撤回", in, out);

        assertFalse(out.allowed(), "撤回后必须拒绝，不得返回已失效授权下的数据");
        assertEquals(DecisionReason.REVOKED, out.reason());
        assertTrue(out.data().isEmpty());
        assertNull(out.pseudonym());
        AuditRecord rec = auditStore.findByRequestId("REQ-RACE-REVOKE-1").orElseThrow();
        assertFalse(rec.allowed());
        assertEquals(DecisionReason.REVOKED, rec.reason());
    }

    @Test
    void auditRecordsAreImmutableAndOrdered() {
        gateway.access(req("REQ-ORD-1", "ORG-A", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT));
        gateway.access(req("REQ-ORD-2", "ORG-X", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT));
        gateway.access(req("REQ-ORD-1", "ORG-A", "P-1001", DataScope.CONDITIONS, Purpose.TREATMENT));

        List<AuditRecord> all = auditStore.all();
        assertEquals(2, all.size());
        assertEquals(1L, all.get(0).seq());
        assertEquals(2L, all.get(1).seq());
        // 记录不可变：返回的是快照
        assertThrows(UnsupportedOperationException.class, () -> all.add(null));
    }
}
