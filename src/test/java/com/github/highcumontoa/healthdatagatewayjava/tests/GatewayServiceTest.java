package com.github.highcumontoa.healthdatagatewayjava.tests;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.service.AuditService;
import com.github.highcumontoa.healthdatagatewayjava.service.AuthorizationService;
import com.github.highcumontoa.healthdatagatewayjava.service.DelegationChainValidator;
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
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 授权边界测试：正常读取 / 超范围 / 目的不符 / 过期 / 已撤回 / 无授权 /
 * 重复提交幂等 / 审计失败 / 脱敏与替代标识稳定性。
 * 每个用例打印：输入、判定依据、最终结论。
 */
class GatewayServiceTest {

    private AuthorizationStore authorizationStore;
    private AuditLog auditLog;
    private AuditService auditService;
    private GatewayService gatewayService;

    private static final Instant NOW = Instant.now();

    @BeforeEach
    void setUp() {
        authorizationStore = new AuthorizationStore();
        auditLog = new AuditLog();
        auditService = new AuditService(auditLog);
        gatewayService = new GatewayService(
                new AuthorizationService(authorizationStore, new DelegationStore(),
                        new DelegationChainValidator(authorizationStore, new DelegationStore())),
                auditService, new PseudonymService(), new HealthDataStore());

        authorizationStore.save(new Authorization(
                "AUTH-VALID", "ORG-A", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS", "MEDICATION"),
                NOW.minus(1, ChronoUnit.DAYS), NOW.plus(30, ChronoUnit.DAYS), false));
        authorizationStore.save(new Authorization(
                "AUTH-EXPIRED", "ORG-A", "PATIENT-002",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                NOW.minus(30, ChronoUnit.DAYS), NOW.minus(1, ChronoUnit.DAYS), false));
    }

    private AccessRequest request(String id, String org, String patient,
                                  String purpose, Set<String> scopes) {
        return new AccessRequest(id, org, patient, purpose, scopes, Instant.now());
    }

    private void printCase(String title, AccessRequest req, GatewayService.GatewayResponse resp) {
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
    void normalRead_returnsMaskedDataAndAudited() {
        AccessRequest req = request("REQ-OK-1", "ORG-A", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"));
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("正常读取", req, resp);

        assertTrue(resp.decision().allowed());
        assertNull(resp.decision().denyReason());
        assertEquals("2型糖尿病", resp.data().get("diagnosis"));
        // 最小必要：未授权范围与不相关字段不出现
        assertFalse(resp.data().containsKey("medication"));
        // 脱敏：不得出现直接标识
        for (String key : HealthDataStore.DIRECT_IDENTIFIERS) {
            assertFalse(resp.data().containsKey(key), "响应不得包含直接标识字段 " + key);
        }
        assertFalse(resp.data().values().stream().anyMatch(v -> v.contains("张三")));
        // 审计：放行也落审计，结论一致
        var audit = auditLog.findByRequestId("REQ-OK-1").orElseThrow();
        assertTrue(audit.allowed());
        assertEquals("ORG-A", audit.requesterId());
        assertEquals(resp.patientPseudonym(), audit.patientPseudonym());
    }

    @Test
    void scopeNotCovered_denied() {
        AccessRequest req = request("REQ-SCOPE-1", "ORG-A", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS", "LAB"));
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("超范围读取", req, resp);

        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.SCOPE_NOT_COVERED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());
        assertFalse(auditLog.findByRequestId("REQ-SCOPE-1").orElseThrow().allowed());
    }

    @Test
    void purposeNotCovered_denied() {
        AccessRequest req = request("REQ-PURPOSE-1", "ORG-A", "PATIENT-001",
                "RESEARCH", Set.of("DIAGNOSIS"));
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("目的不符", req, resp);

        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.PURPOSE_NOT_COVERED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());
    }

    @Test
    void expiredAuthorization_denied() {
        AccessRequest req = request("REQ-EXPIRED-1", "ORG-A", "PATIENT-002",
                "TREATMENT", Set.of("DIAGNOSIS"));
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("授权过期", req, resp);

        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.EXPIRED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());
    }

    @Test
    void revokedAuthorization_denied() {
        authorizationStore.revoke("AUTH-VALID");
        AccessRequest req = request("REQ-REVOKE-1", "ORG-A", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"));
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("授权已撤回", req, resp);

        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.REVOKED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());
    }

    @Test
    void noAuthorization_denied() {
        AccessRequest req = request("REQ-NONE-1", "ORG-B", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"));
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("无任何授权", req, resp);

        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.NO_AUTHORIZATION, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());
    }

    @Test
    void duplicateRequest_idempotentNoDuplicateAudit() {
        AccessRequest req = request("REQ-DUP-1", "ORG-A", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"));
        GatewayService.GatewayResponse first = gatewayService.handle(req);
        GatewayService.GatewayResponse second = gatewayService.handle(req);
        printCase("重复提交-第一次", req, first);
        printCase("重复提交-第二次", req, second);

        assertTrue(first.decision().allowed());
        assertTrue(second.decision().allowed());
        assertEquals(first.data(), second.data());
        // 同一 requestId 只产生一条审计记录
        assertEquals(1, auditLog.findAll().stream()
                .filter(r -> r.requestId().equals("REQ-DUP-1")).count());
        assertEquals(1, auditLog.findAll().size());
    }

    @Test
    void auditUnavailable_accessDenied() {
        auditService.setAvailable(false);
        AccessRequest req = request("REQ-AUDIT-1", "ORG-A", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"));
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("审计环节不可用", req, resp);

        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.AUDIT_UNAVAILABLE, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());
        // 审计不可用时不得留下“放行”记录
        assertTrue(auditLog.findAll().stream().noneMatch(r -> r.allowed()));
    }

    @Test
    void pseudonym_stablePerRequester_unlinkableAcrossRequesters() {
        AccessRequest req1 = request("REQ-PSN-1", "ORG-A", "PATIENT-001",
                "TREATMENT", Set.of("DIAGNOSIS"));
        GatewayService.GatewayResponse r1 = gatewayService.handle(req1);
        GatewayService.GatewayResponse r2 = gatewayService.handle(
                request("REQ-PSN-2", "ORG-A", "PATIENT-001", "TREATMENT", Set.of("DIAGNOSIS")));

        // 同一请求方对同一对象：替代标识稳定
        assertEquals(r1.patientPseudonym(), r2.patientPseudonym());

        // 给 ORG-B 授权同一患者，比较跨请求方标识
        authorizationStore.save(new Authorization(
                "AUTH-B", "ORG-B", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                NOW.minus(1, ChronoUnit.DAYS), NOW.plus(30, ChronoUnit.DAYS), false));
        GatewayService.GatewayResponse r3 = gatewayService.handle(
                request("REQ-PSN-3", "ORG-B", "PATIENT-001", "TREATMENT", Set.of("DIAGNOSIS")));

        System.out.println("==== 替代标识稳定性 ====");
        System.out.println("[输入] ORG-A x2, ORG-B x1, 同一患者 PATIENT-001");
        System.out.println("[最终结论] ORG-A 第一次=" + r1.patientPseudonym()
                + " ORG-A 第二次=" + r2.patientPseudonym()
                + " ORG-B=" + r3.patientPseudonym());

        // 不同请求方之间不可关联
        assertNotEquals(r1.patientPseudonym(), r3.patientPseudonym());
        // 替代标识不得包含原始患者标识
        assertFalse(r1.patientPseudonym().contains("PATIENT-001"));
    }
}
