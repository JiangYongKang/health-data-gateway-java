package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.AuditRecord;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.store.HealthDataStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 网关编排，保证判定、脱敏、审计三者结论一致：
 * 1. 幂等去重：同一 requestId 直接回放首次审计结论，不产生重复审计；
 * 2. 授权判定：逐项校验并记录判定依据；
 * 3. 审计先行：判定结论先落审计，审计不可用则拒绝（绝不放行）；
 * 4. 取数前复核：放行后、读取数据前再次校验授权，
 *    关闭“判定后被撤回”的窗口，保证最终结果与撤回后状态一致；
 * 5. 脱敏输出：响应仅含授权范围内的非标识字段与替代标识。
 */
@Service
public class GatewayService {

    private static final Logger log = LoggerFactory.getLogger(GatewayService.class);

    public record GatewayResponse(Decision decision, Map<String, String> data, String patientPseudonym) {
    }

    private final AuthorizationService authorizationService;
    private final AuditService auditService;
    private final PseudonymService pseudonymService;
    private final HealthDataStore healthDataStore;

    public GatewayService(AuthorizationService authorizationService,
                          AuditService auditService,
                          PseudonymService pseudonymService,
                          HealthDataStore healthDataStore) {
        this.authorizationService = authorizationService;
        this.auditService = auditService;
        this.pseudonymService = pseudonymService;
        this.healthDataStore = healthDataStore;
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
            // 2. 授权判定
            decision = authorizationService.evaluate(request);

            // 3. 审计先行：审计不可用时拒绝访问
            try {
                auditService.record(request, decision, pseudonym);
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

        // 4. 取数前复核：若授权在判定后被撤回，以撤回后的状态为准
        Decision recheck = authorizationService.evaluate(request);
        if (!recheck.allowed()) {
            List<String> basis = new ArrayList<>(recheck.basis());
            basis.add("recheck-before-read: 放行后复核未通过，拒绝返回数据");
            Decision finalDeny = Decision.deny(recheck.denyReason(), basis);
            // 追加一条独立的复核审计记录（requestId#recheck），不改写首条记录
            try {
                auditService.record(
                        new AccessRequest(request.requestId() + "#recheck",
                                request.requesterId(), request.patientId(),
                                request.purpose(), request.scopes(), request.requestedAt()),
                        finalDeny, pseudonym);
            } catch (IllegalStateException e) {
                basis.add("audit=UNAVAILABLE 复核结论审计失败: " + e.getMessage());
                finalDeny = Decision.deny(DenyReason.AUDIT_UNAVAILABLE, basis);
            }
            log.info("[gateway] recheck denied requestId={} reason={}",
                    request.requestId(), finalDeny.denyReason());
            return new GatewayResponse(finalDeny, Map.of(), pseudonym);
        }

        // 5. 脱敏输出：仅授权范围内的非标识字段
        Map<String, String> raw = healthDataStore.read(request.patientId(), request.scopes())
                .orElse(Map.of());
        Map<String, String> masked = new LinkedHashMap<>();
        raw.forEach((k, v) -> {
            if (!HealthDataStore.DIRECT_IDENTIFIERS.contains(k)) {
                masked.put(k, v);
            }
        });
        log.info("[gateway] allow requestId={} fields={}", request.requestId(), masked.keySet());
        return new GatewayResponse(decision, masked, pseudonym);
    }
}
