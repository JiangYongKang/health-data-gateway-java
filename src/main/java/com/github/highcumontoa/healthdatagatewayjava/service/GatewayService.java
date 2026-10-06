package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.AuditRecord;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.Delegation;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.store.HealthDataStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 网关编排，保证判定、脱敏、审计三者结论一致：
 * 1. 幂等去重：同一 requestId 直接回放首次审计结论，不产生重复审计；
 * 2. 授权判定：直接授权走 {@link AuthorizationService}，
 *    转授访问走 {@link DelegationService}（沿链路逐级判定）；
 * 3. 审计先行：判定结论先落审计（转授访问记录转授来源），审计不可用则拒绝（绝不放行）；
 * 4. 取数前复核：放行后、读取数据前再次校验授权；转授访问的“复核+取数”在链路锁内原子完成，
 *    与原始授权撤回/级联撤回互斥，关闭并发窗口；
 * 5. 脱敏输出：响应仅含授权范围内的非标识字段与替代标识（以实际访问方视角派生）。
 */
@Service
public class GatewayService {

    private static final Logger log = LoggerFactory.getLogger(GatewayService.class);

    public record GatewayResponse(Decision decision, Map<String, String> data, String patientPseudonym) {
    }

    /** 取数复核阶段的内部结果。 */
    private record ReadOutcome(Decision recheck, Map<String, String> raw) {
    }

    private final AuthorizationService authorizationService;
    private final AuditService auditService;
    private final PseudonymService pseudonymService;
    private final HealthDataStore healthDataStore;
    private final DelegationService delegationService;

    @Autowired
    public GatewayService(AuthorizationService authorizationService,
                          AuditService auditService,
                          PseudonymService pseudonymService,
                          HealthDataStore healthDataStore,
                          DelegationService delegationService) {
        this.authorizationService = authorizationService;
        this.auditService = auditService;
        this.pseudonymService = pseudonymService;
        this.healthDataStore = healthDataStore;
        this.delegationService = delegationService;
    }

    /** 兼容构造函数：仅直接授权访问（不启用转授能力），供既有测试与最小装配使用。 */
    public GatewayService(AuthorizationService authorizationService,
                          AuditService auditService,
                          PseudonymService pseudonymService,
                          HealthDataStore healthDataStore) {
        this(authorizationService, auditService, pseudonymService, healthDataStore, null);
    }

    public GatewayResponse handle(AccessRequest request) {
        String pseudonym = pseudonymService.pseudonymFor(request.requesterId(), request.patientId());

        // 1. 幂等去重：同一 requestId 重复提交，回放首次审计结论，不产生新审计
        Optional<AuditRecord> existing = auditService.findByRequestId(request.requestId());
        Decision decision;
        if (existing.isPresent()) {
            AuditRecord first = existing.get();
            List<String> basis = new ArrayList<>(first.basis());
            basis.add("idempotent-replay: requestId=" + request.requestId() + " 已存在审计结论，不再重复审计");
            decision = new Decision(first.allowed(), first.denyReason(), basis);
            log.info("[gateway] replay requestId={} allowed={} reason={}",
                    request.requestId(), decision.allowed(), decision.denyReason());
        } else {
            // 2. 授权判定（直接授权 / 转授链路）
            decision = evaluate(request);

            // 3. 审计先行：审计不可用时拒绝访问
            try {
                auditService.record(request, decision, pseudonym, traceOf(request).orElse(null));
            } catch (IllegalStateException e) {
                List<String> basis = new ArrayList<>(decision.basis());
                basis.add("audit=UNAVAILABLE 审计环节不可用，按安全策略拒绝访问: " + e.getMessage());
                Decision denied = Decision.deny(DenyReason.AUDIT_UNAVAILABLE, basis);
                log.warn("[gateway] audit unavailable, deny requestId={}", request.requestId());
                return new GatewayResponse(denied, Map.of(), pseudonym);
            }
        }

        if (!decision.allowed()) {
            return new GatewayResponse(decision, Map.of(), pseudonym);
        }

        // 4. 取数前复核（转授访问：复核+取数在链路锁内原子完成，与撤回互斥）
        ReadOutcome outcome;
        if (request.viaDelegation() && delegationService != null) {
            String rootId = delegationService.rootAuthorizationOf(request.delegationId()).orElse(null);
            if (rootId == null) {
                // 理论上不会走到（判定已放行），防御性拒绝
                return denyAfterAudit(request, pseudonym, decision,
                        Decision.deny(DenyReason.DELEGATION_NOT_FOUND,
                                List.of("recheck-before-read: 转授关系已不存在")));
            }
            outcome = delegationService.withChainLock(rootId,
                    () -> recheckAndRead(request));
        } else {
            outcome = recheckAndRead(request);
        }

        Decision recheck = outcome.recheck();
        if (!recheck.allowed()) {
            return denyAfterAudit(request, pseudonym, decision, recheck);
        }

        // 5. 脱敏输出：仅授权范围内的非标识字段
        Map<String, String> masked = new LinkedHashMap<>();
        outcome.raw().forEach((k, v) -> {
            if (!HealthDataStore.DIRECT_IDENTIFIERS.contains(k)) {
                masked.put(k, v);
            }
        });
        log.info("[gateway] allow requestId={} viaDelegation={} fields={}",
                request.requestId(), request.delegationId(), masked.keySet());
        return new GatewayResponse(decision, masked, pseudonym);
    }

    private Decision evaluate(AccessRequest request) {
        if (request.viaDelegation()) {
            if (delegationService == null) {
                return Decision.deny(DenyReason.DELEGATION_NOT_FOUND,
                        List.of("delegation-unsupported: 当前网关未启用转授能力"));
            }
            return delegationService.evaluateDelegatedAccess(request);
        }
        return authorizationService.evaluate(request);
    }

    /** 复核授权并在同一临界区内读取原始数据（转授场景由链路锁包裹）。 */
    private ReadOutcome recheckAndRead(AccessRequest request) {
        Decision recheck = evaluate(request);
        if (!recheck.allowed()) {
            List<String> basis = new ArrayList<>(recheck.basis());
            basis.add("recheck-before-read: 放行后复核未通过，拒绝返回数据");
            return new ReadOutcome(Decision.deny(recheck.denyReason(), basis), Map.of());
        }
        Map<String, String> raw = healthDataStore.read(request.patientId(), request.scopes())
                .orElse(Map.of());
        return new ReadOutcome(recheck, raw);
    }

    /** 复核未通过：追加独立的 #recheck 审计记录（不改写首条），返回无数据拒绝。 */
    private GatewayResponse denyAfterAudit(AccessRequest request, String pseudonym,
                                           Decision original, Decision finalDeny) {
        try {
            AccessRequest recheckRequest = new AccessRequest(
                    request.requestId() + "#recheck",
                    request.requesterId(), request.patientId(),
                    request.purpose(), request.scopes(), request.requestedAt(),
                    request.delegationId());
            auditService.record(recheckRequest, finalDeny, pseudonym,
                    traceOf(request).orElse(null));
        } catch (IllegalStateException e) {
            List<String> basis = new ArrayList<>(finalDeny.basis());
            basis.add("audit=UNAVAILABLE 复核结论审计失败: " + e.getMessage());
            finalDeny = Decision.deny(DenyReason.AUDIT_UNAVAILABLE, basis);
        }
        log.info("[gateway] recheck denied requestId={} viaDelegation={} reason={}",
                request.requestId(), request.delegationId(), finalDeny.denyReason());
        return new GatewayResponse(finalDeny, Map.of(), pseudonym);
    }

    /** 解析本次访问所依据的转授来源（供审计记录）。 */
    private Optional<AuditService.DelegationTrace> traceOf(AccessRequest request) {
        if (!request.viaDelegation() || delegationService == null) {
            return Optional.empty();
        }
        return delegationService.findDelegation(request.delegationId())
                .map(d -> new AuditService.DelegationTrace(
                        d.delegationId(), d.rootAuthorizationId(), d.depth()));
    }
}
