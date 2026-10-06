package com.github.highcumontoa.healthdatagatewayjava.tests;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.Delegation;
import com.github.highcumontoa.healthdatagatewayjava.domain.DelegationRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.service.AuditService;
import com.github.highcumontoa.healthdatagatewayjava.service.ChainLock;
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
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 授权转授（委托）行为测试：
 * 正常转授读取 / 越权转授（范围/目的/有效期）被拒 / 深度上限 / 环状委托 /
 * 重复转授幂等 / 原始授权撤回级联收敛 / 转授自身撤回与过期（可区分原因）/
 * 被转授方视角脱敏标识稳定且跨机构不可关联 / 审计体现转授来源。
 * 每例打印：输入、判定依据、最终结论。
 */
class DelegationServiceTest {

    private AuthorizationStore authorizationStore;
    private DelegationStore delegationStore;
    private AuditLog auditLog;
    private AuditService auditService;
    private DelegationService delegationService;
    private GatewayService gatewayService;

    private static final Instant NOW = Instant.now();

    @BeforeEach
    void setUp() {
        authorizationStore = new AuthorizationStore();
        delegationStore = new DelegationStore();
        auditLog = new AuditLog();
        auditService = new AuditService(auditLog);
        delegationService = new DelegationService(
                authorizationStore, delegationStore, new ChainLock(), auditService);
        gatewayService = new GatewayService(
                new com.github.highcumontoa.healthdatagatewayjava.service.AuthorizationService(
                        authorizationStore),
                auditService, new PseudonymService(), new HealthDataStore(), delegationService);

        // ORG-A 持有 PATIENT-001 的 TREATMENT/[DIAGNOSIS,MEDICATION] 授权，有效期 30 天
        authorizationStore.save(new Authorization(
                "AUTH-ROOT", "ORG-A", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS", "MEDICATION"),
                NOW.minus(1, ChronoUnit.DAYS), NOW.plus(30, ChronoUnit.DAYS), false));
    }

    private DelegationRequest delegationRequest(String id, String from, String to,
                                                String purpose, Set<String> scopes,
                                                Instant fromTime, Instant untilTime) {
        return new DelegationRequest(id, from, to, "PATIENT-001", purpose, scopes,
                fromTime, untilTime, Instant.now());
    }

    private DelegationRequest narrowRequest(String id, String from, String to,
                                            String purpose, Set<String> scopes) {
        return delegationRequest(id, from, to, purpose, scopes,
                NOW.minusSeconds(60), NOW.plus(20, ChronoUnit.DAYS));
    }

    private AccessRequest access(String reqId, String org, String purpose,
                                 Set<String> scopes, String delegationId) {
        return new AccessRequest(reqId, org, "PATIENT-001", purpose, scopes,
                Instant.now(), delegationId);
    }

    private void printCase(String title, Object input,
                           com.github.highcumontoa.healthdatagatewayjava.domain.Decision decision,
                           Object extra) {
        System.out.println("==== " + title + " ====");
        System.out.println("[输入] " + input);
        System.out.println("[判定依据]");
        decision.basis().forEach(b -> System.out.println("  - " + b));
        System.out.println("[最终结论] allowed=" + decision.allowed()
                + " reason=" + decision.denyReason() + " " + (extra == null ? "" : extra));
    }

    private Delegation grantOrFail(String id, String from, String to,
                                   String purpose, Set<String> scopes) {
        DelegationService.DelegationResult r =
                delegationService.createDelegation(narrowRequest(id, from, to, purpose, scopes));
        assertTrue(r.decision().allowed(),
                "转授应成功，但被拒绝: " + r.decision().denyReason() + " " + r.decision().basis());
        assertNotNull(r.delegation());
        return r.delegation();
    }

    @Test
    void validDelegation_delegateeReadsMaskedData_withTraceableSource() {
        Delegation d = grantOrFail("DEL-1", "ORG-A", "ORG-B",
                "TREATMENT", Set.of("DIAGNOSIS"));
        assertEquals(1, d.depth());
        assertEquals("AUTH-ROOT", d.rootAuthorizationId());
        assertNull(d.parentDelegationId());

        AccessRequest req = access("REQ-DEL-1", "ORG-B", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-1");
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("正常转授读取", req, resp.decision(),
                "data=" + resp.data() + " pseudonym=" + resp.patientPseudonym());

        assertTrue(resp.decision().allowed());
        assertEquals("2型糖尿病", resp.data().get("diagnosis"));
        assertFalse(resp.data().containsKey("medication"), "最小必要：未转授范围不出现");
        assertFalse(resp.data().containsKey("name"), "脱敏：直接标识不出网");

        // 审计体现转授来源
        var record = auditLog.findByRequestId("REQ-DEL-1").orElseThrow();
        assertTrue(record.allowed());
        assertEquals("DEL-1", record.delegationId());
        assertEquals("AUTH-ROOT", record.rootAuthorizationId());
        assertEquals(1, record.delegationDepth());
        // 转授授权事件也有一条审计
        var grant = auditLog.findByRequestId("DEL-1").orElseThrow();
        assertTrue(grant.allowed());
    }

    @Test
    void scopeExceedingDelegation_denied() {
        DelegationRequest req = narrowRequest("DEL-SCOPE", "ORG-A", "ORG-B",
                "TREATMENT", Set.of("DIAGNOSIS", "LAB"));
        DelegationService.DelegationResult r = delegationService.createDelegation(req);
        printCase("越权转授-范围超出", req, r.decision(), null);

        assertFalse(r.decision().allowed());
        assertEquals(DenyReason.DELEGATION_SCOPE_EXCEEDED, r.decision().denyReason());
        assertNull(r.delegation());
        // 拒绝不产生转授关系，也不产生授权审计
        assertTrue(delegationStore.findById("DEL-SCOPE").isEmpty());
        assertTrue(auditLog.findByRequestId("DEL-SCOPE").isEmpty());
    }

    @Test
    void purposeExceedingDelegation_denied() {
        DelegationRequest req = narrowRequest("DEL-PURPOSE", "ORG-A", "ORG-B",
                "RESEARCH", Set.of("DIAGNOSIS"));
        DelegationService.DelegationResult r = delegationService.createDelegation(req);
        printCase("越权转授-目的超出", req, r.decision(), null);

        assertFalse(r.decision().allowed());
        assertEquals(DenyReason.DELEGATION_PURPOSE_EXCEEDED, r.decision().denyReason());
    }

    @Test
    void durationExceedingDelegation_denied() {
        Authorization root = authorizationStore.findById("AUTH-ROOT").orElseThrow();
        // 期望有效期超出原始授权的失效时间
        DelegationRequest req = delegationRequest("DEL-TIME", "ORG-A", "ORG-B",
                "TREATMENT", Set.of("DIAGNOSIS"),
                root.validFrom(), root.validUntil().plus(1, ChronoUnit.DAYS));
        DelegationService.DelegationResult r = delegationService.createDelegation(req);
        printCase("越权转授-有效期超过原始授权", req, r.decision(), null);

        assertFalse(r.decision().allowed());
        assertEquals(DenyReason.DELEGATION_DURATION_EXCEEDED, r.decision().denyReason());
    }

    @Test
    void delegationWithoutValidSource_denied() {
        DelegationRequest req = narrowRequest("DEL-NOSRC", "ORG-X", "ORG-B",
                "TREATMENT", Set.of("DIAGNOSIS"));
        DelegationService.DelegationResult r = delegationService.createDelegation(req);
        printCase("无上游授权的转授", req, r.decision(), null);

        assertFalse(r.decision().allowed());
        assertEquals(DenyReason.DELEGATION_SOURCE_NOT_COVERED, r.decision().denyReason());
    }

    @Test
    void delegationChainBeyondMaxDepth_denied() {
        // AUTH-ROOT(depth0) -> DEL-A(d1,ORG-B) -> DEL-B(d2,ORG-C) -> DEL-C(d3,ORG-D)
        // ORG-D 再转授将达到 depth4 > 上限3，必须拒绝
        grantOrFail("DEL-A", "ORG-A", "ORG-B", "TREATMENT", Set.of("DIAGNOSIS"));
        grantOrFail("DEL-B", "ORG-B", "ORG-C", "TREATMENT", Set.of("DIAGNOSIS"));
        grantOrFail("DEL-C", "ORG-C", "ORG-D", "TREATMENT", Set.of("DIAGNOSIS"));

        DelegationRequest req = narrowRequest("DEL-TOODEEP", "ORG-D", "ORG-E",
                "TREATMENT", Set.of("DIAGNOSIS"));
        DelegationService.DelegationResult r = delegationService.createDelegation(req);
        printCase("转授深度超过上限", req, r.decision(), null);

        assertFalse(r.decision().allowed());
        assertEquals(DenyReason.DELEGATION_TOO_DEEP, r.decision().denyReason());

        // 恰好达到上限深度3的转授仍可访问
        AccessRequest ok = access("REQ-DEPTH-OK", "ORG-D", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-C");
        GatewayService.GatewayResponse resp = gatewayService.handle(ok);
        printCase("达到深度上限仍可访问", ok, resp.decision(), "data=" + resp.data());
        assertTrue(resp.decision().allowed());
        assertEquals(3, auditLog.findByRequestId("REQ-DEPTH-OK").orElseThrow().delegationDepth());
    }

    @Test
    void cyclicDelegation_denied() {
        grantOrFail("DEL-CY1", "ORG-A", "ORG-B", "TREATMENT", Set.of("DIAGNOSIS"));
        // ORG-B 试图转回链路中已存在的 ORG-A，构成环，必须拒绝
        DelegationRequest back = narrowRequest("DEL-CY2", "ORG-B", "ORG-A",
                "TREATMENT", Set.of("DIAGNOSIS"));
        DelegationService.DelegationResult r = delegationService.createDelegation(back);
        printCase("环状委托被拒", back, r.decision(), null);

        assertFalse(r.decision().allowed());
        assertEquals(DenyReason.DELEGATION_CYCLE, r.decision().denyReason());
        assertTrue(delegationStore.findById("DEL-CY2").isEmpty());

        // 转授给自己也按环路拒绝
        DelegationRequest self = narrowRequest("DEL-SELF", "ORG-B", "ORG-B",
                "TREATMENT", Set.of("DIAGNOSIS"));
        DelegationService.DelegationResult rs = delegationService.createDelegation(self);
        assertEquals(DenyReason.DELEGATION_CYCLE, rs.decision().denyReason());
    }

    @Test
    void duplicateDelegation_idempotent_noDuplicateRelationOrAudit() {
        DelegationRequest req = narrowRequest("DEL-DUP", "ORG-A", "ORG-B",
                "TREATMENT", Set.of("DIAGNOSIS"));
        DelegationService.DelegationResult first = delegationService.createDelegation(req);
        DelegationService.DelegationResult second = delegationService.createDelegation(req);
        printCase("重复转授-第一次", req, first.decision(),
                "delegation=" + (first.delegation() == null ? null : first.delegation().delegationId()));
        printCase("重复转授-第二次", req, second.decision(),
                "delegation=" + (second.delegation() == null ? null : second.delegation().delegationId()));

        assertTrue(first.decision().allowed());
        assertTrue(second.decision().allowed());
        assertSame(first.delegation(), second.delegation(), "重复提交回放同一条关系");
        // 只有一条转授关系
        assertEquals(1, delegationStore.findByRootAuthorization("AUTH-ROOT").size());
        // 只有一条转授授权审计
        assertEquals(1, auditLog.findAll().stream()
                .filter(a -> a.requestId().equals("DEL-DUP")).count());
    }

    @Test
    void rootAuthorizationRevoked_delegatedAccessCascades_distinguishableReason() {
        grantOrFail("DEL-CASC", "ORG-A", "ORG-B", "TREATMENT", Set.of("DIAGNOSIS"));

        // 级联撤回原始授权
        int cascaded = delegationService.revokeRootAndCascade("AUTH-ROOT");
        System.out.println("==== 原始授权撤回后级联收敛 ====");
        System.out.println("[输入] revoke AUTH-ROOT，级联撤回数量=" + cascaded);
        assertEquals(1, cascaded);
        assertTrue(delegationStore.findById("DEL-CASC").orElseThrow().revoked());

        AccessRequest req = access("REQ-CASC", "ORG-B", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-CASC");
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("原始授权撤回后的转授访问", req, resp.decision(),
                "data=" + resp.data());

        assertFalse(resp.decision().allowed());
        // 原始授权失效：REVOKED（区别于转授自身失效 DELEGATION_REVOKED）
        assertEquals(DenyReason.REVOKED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());
    }

    @Test
    void delegationItselfRevoked_distinguishableReason() {
        grantOrFail("DEL-D", "ORG-A", "ORG-B", "TREATMENT", Set.of("DIAGNOSIS"));
        assertTrue(delegationService.revokeDelegation("DEL-D"));

        AccessRequest req = access("REQ-DREV", "ORG-B", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-D");
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("转授关系自身被撤回", req, resp.decision(), "data=" + resp.data());

        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.DELEGATION_REVOKED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());

        // 原始授权持有人 ORG-A 的直接访问不受影响
        AccessRequest direct = access("REQ-DIRECT-STILL-OK", "ORG-A", "TREATMENT",
                Set.of("DIAGNOSIS"), null);
        GatewayService.GatewayResponse directResp = gatewayService.handle(direct);
        assertTrue(directResp.decision().allowed(), "撤回转授不影响原始授权的直接访问");
    }

    @Test
    void delegationExpired_distinguishableReason() {
        // 转授有效期已过，但落在原始授权窗口内、原始授权仍有效
        DelegationRequest req = delegationRequest("DEL-EXP", "ORG-A", "ORG-B",
                "TREATMENT", Set.of("DIAGNOSIS"),
                NOW.minus(1, ChronoUnit.DAYS).plusSeconds(1), NOW.minus(1, ChronoUnit.HOURS));
        DelegationService.DelegationResult created = delegationService.createDelegation(req);
        assertTrue(created.decision().allowed());

        AccessRequest accessReq = access("REQ-DEXP", "ORG-B", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-EXP");
        GatewayService.GatewayResponse resp = gatewayService.handle(accessReq);
        printCase("转授过期（原始授权仍有效）", accessReq, resp.decision(),
                "data=" + resp.data());

        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.DELEGATION_EXPIRED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());
    }

    @Test
    void delegateePseudonym_stableAndUnlinkable() {
        grantOrFail("DEL-PSN", "ORG-A", "ORG-B", "TREATMENT", Set.of("DIAGNOSIS"));

        AccessRequest r1 = access("REQ-PSN-D1", "ORG-B", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-PSN");
        AccessRequest r2 = access("REQ-PSN-D2", "ORG-B", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-PSN");
        GatewayService.GatewayResponse g1 = gatewayService.handle(r1);
        GatewayService.GatewayResponse g2 = gatewayService.handle(r2);
        // ORG-A 直接访问同一患者
        GatewayService.GatewayResponse ga = gatewayService.handle(
                access("REQ-PSN-A", "ORG-A", "TREATMENT", Set.of("DIAGNOSIS"), null));

        System.out.println("==== 被转授方替代标识 ====");
        System.out.println("[输入] ORG-B 经转授访问 x2，ORG-A 直接访问，同一患者 PATIENT-001");
        System.out.println("[最终结论] ORG-B#1=" + g1.patientPseudonym()
                + " ORG-B#2=" + g2.patientPseudonym() + " ORG-A=" + ga.patientPseudonym());

        assertEquals(g1.patientPseudonym(), g2.patientPseudonym(), "同一被转授方视角稳定");
        assertNotEquals(g1.patientPseudonym(), ga.patientPseudonym(),
                "被转授方与转授方之间不可相互关联");
        assertFalse(g1.patientPseudonym().contains("PATIENT-001"));
    }

    @Test
    void intermediateDelegationRevoked_leafAccessDenied_delegationRevoked() {
        // AUTH-ROOT -> DEL-M1(ORG-B) -> DEL-M2(ORG-C)，撤回中间级 DEL-M1
        grantOrFail("DEL-M1", "ORG-A", "ORG-B", "TREATMENT", Set.of("DIAGNOSIS"));
        grantOrFail("DEL-M2", "ORG-B", "ORG-C", "TREATMENT", Set.of("DIAGNOSIS"));
        assertTrue(delegationService.revokeDelegation("DEL-M1"));

        AccessRequest req = access("REQ-MID-REV", "ORG-C", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-M2");
        GatewayService.GatewayResponse resp = gatewayService.handle(req);
        printCase("多级链路中间级被撤回", req, resp.decision(), "data=" + resp.data());

        assertFalse(resp.decision().allowed());
        assertEquals(DenyReason.DELEGATION_REVOKED, resp.decision().denyReason());
        assertTrue(resp.data().isEmpty());

        // 上游 ORG-B 已不能再继续扩大转授（其来源已失效）
        DelegationRequest more = narrowRequest("DEL-MID-EXPAND", "ORG-B", "ORG-X",
                "TREATMENT", Set.of("DIAGNOSIS"));
        DelegationService.DelegationResult r = delegationService.createDelegation(more);
        printCase("中间级失效后转授方再转授", more, r.decision(), null);
        assertFalse(r.decision().allowed());
    }

    @Test
    void wrongDelegateeOrUnknownDelegation_denied() {
        grantOrFail("DEL-W", "ORG-A", "ORG-B", "TREATMENT", Set.of("DIAGNOSIS"));

        // 非被转授方冒用转授关系
        AccessRequest wrongParty = access("REQ-WP", "ORG-C", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-W");
        GatewayService.GatewayResponse rp = gatewayService.handle(wrongParty);
        printCase("非被转授方冒用", wrongParty, rp.decision(), null);
        assertEquals(DenyReason.DELEGATION_PARTY_MISMATCH, rp.decision().denyReason());

        // 引用不存在的转授关系
        AccessRequest missing = access("REQ-MISS", "ORG-B", "TREATMENT",
                Set.of("DIAGNOSIS"), "DEL-NOT-EXIST");
        GatewayService.GatewayResponse rm = gatewayService.handle(missing);
        printCase("引用不存在的转授", missing, rm.decision(), null);
        assertEquals(DenyReason.DELEGATION_NOT_FOUND, rm.decision().denyReason());
    }
}
