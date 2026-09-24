package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.model.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.model.AccessResponse;
import com.github.highcumontoa.healthdatagatewayjava.model.AuditRecord;
import com.github.highcumontoa.healthdatagatewayjava.model.AuthzResult;
import com.github.highcumontoa.healthdatagatewayjava.model.DecisionReason;
import com.github.highcumontoa.healthdatagatewayjava.model.Grant;
import com.github.highcumontoa.healthdatagatewayjava.model.PatientRecord;
import com.github.highcumontoa.healthdatagatewayjava.store.AuditStore;
import com.github.highcumontoa.healthdatagatewayjava.store.GrantStore;
import com.github.highcumontoa.healthdatagatewayjava.store.PatientStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * 访问网关：编排 判定 -> 审计 -> 脱敏输出。
 *
 * 一致性保证：
 * - 判定、脱敏输出、审计三者基于同一次评估结论；
 * - 同一 requestId 重复提交只产生一条审计记录（命中既有记录并标记 replayed）；
 * - 审计不可用时 fail-closed，任何新请求一律拒绝（AUDIT_UNAVAILABLE）；
 * - 授权在访问过程中被撤回：通过“评估-钩子-锁内复核-原子写审计”顺序，
 *   撤回在最终复核前生效则结果为 REVOKED 且不返回数据；
 * - 放行的数据在审计记录成功落库之后才构建返回。
 */
@Service
public class AccessGatewayService {

    private static final Logger log = LoggerFactory.getLogger(AccessGatewayService.class);

    private final GrantStore grantStore;
    private final PatientStore patientStore;
    private final AuditStore auditStore;
    private final AuthzEvaluator authzEvaluator;
    private final DataSanitizer dataSanitizer;
    private final Clock clock;

    /** 测试钩子：第一次评估通过后、锁内最终复核前执行（用于确定性模拟撤回）。 */
    private volatile Consumer<AccessRequest> preAuditHook = r -> { };

    public AccessGatewayService(GrantStore grantStore, PatientStore patientStore, AuditStore auditStore,
                                AuthzEvaluator authzEvaluator, DataSanitizer dataSanitizer, Clock clock) {
        this.grantStore = grantStore;
        this.patientStore = patientStore;
        this.auditStore = auditStore;
        this.authzEvaluator = authzEvaluator;
        this.dataSanitizer = dataSanitizer;
        this.clock = clock;
    }

    public void setPreAuditHook(Consumer<AccessRequest> hook) {
        this.preAuditHook = hook == null ? r -> { } : hook;
    }

    public AccessResponse access(AccessRequest request) {
        validate(request);
        log.info("[访问网关] 输入 requestId={}, requesterId={}, patientId={}, scope={}, purpose={}",
                request.requestId(), request.requesterId(), request.patientId(),
                request.scope(), request.purpose());

        // 1) 幂等：已有同 requestId 审计记录时，直接重放该结论，不新增审计
        Optional<AuditRecord> existing = auditStore.findByRequestId(request.requestId());
        if (existing.isPresent()) {
            AuditRecord rec = existing.get();
            log.info("[访问网关] requestId={} 命中既有审计 seq={}，按幂等重放，不新增审计",
                    request.requestId(), rec.seq());
            return buildReplay(rec);
        }

        // 2) 首次授权判定
        AuthzResult first = authzEvaluator.evaluate(request);

        // 3) 若首次判定放行：在“撤回窗口”钩子后，于授权锁内做最终复核并原子写审计
        if (first.allowed()) {
            return handleAllowed(request, first);
        }

        // 4) 拒绝路径：写拒绝审计；审计不可用则 fail-closed（统一 AUDIT_UNAVAILABLE）
        try {
            AuditRecord candidate = candidateOf(request, first, false);
            AuditRecord rec = auditStore.append(candidate).record();
            log.info("[访问网关] requestId={} 判定依据: {} | 最终结论: {} seq={}",
                    request.requestId(), rec.decisionBasis(), rec.reason(), rec.seq());
            return new AccessResponse(request.requestId(), false, rec.reason(), rec.decisionBasis(),
                    false, rec.seq(), null, Map.of());
        } catch (AuditUnavailableException e) {
            return failClosed(request, "审计环节不可用，依据 fail-closed 策略拒绝访问");
        }
    }

    private AccessResponse failClosed(AccessRequest request, String basis) {
        log.warn("[访问网关] requestId={} 审计不可用，fail-closed 拒绝（不放行任何数据）", request.requestId());
        return new AccessResponse(request.requestId(), false, DecisionReason.AUDIT_UNAVAILABLE,
                basis, false, -1L, null, Map.of());
    }

    private AccessResponse handleAllowed(AccessRequest request, AuthzResult first) {
        // 访问途中撤回的确定性注入点
        preAuditHook.accept(request);

        Optional<Grant> grantOpt = grantStore.findActive(request.requesterId(), request.patientId());
        if (grantOpt.isEmpty()) {
            return denyAndAudit(request, AuthzResult.deny(DecisionReason.GRANT_NOT_FOUND,
                    "最终复核时授权已不存在"));
        }
        Grant grant = grantOpt.get();
        Object lock = grantStore.lockFor(grant.getGrantId());

        synchronized (lock) {
            // 锁内最终复核；撤回操作同样获取该锁，因此此处的结论与撤回状态严格一致
            AuthzResult finalDecision = authzEvaluator.evaluate(request);
            if (!finalDecision.allowed()) {
                try {
                    AuditRecord rec = auditStore.append(candidateOf(request, finalDecision, false)).record();
                    log.info("[访问网关] requestId={} 锁内复核拒绝，判定依据: {} | 最终结论: {} seq={}",
                            request.requestId(), rec.decisionBasis(), rec.reason(), rec.seq());
                    return new AccessResponse(request.requestId(), false, rec.reason(),
                            rec.decisionBasis(), false, rec.seq(), null, Map.of());
                } catch (AuditUnavailableException e) {
                    return failClosed(request, "审计环节不可用，依据 fail-closed 策略拒绝访问");
                }
            }

            // 审计先于数据：审计失败则不返回任何受保护数据
            AuditRecord rec;
            try {
                AuditStore.AppendResult result = auditStore.append(candidateOf(request, finalDecision, false));
                rec = result.record();
                if (!result.created()) {
                    // 并发重复提交：另一个线程已写入，重放其结论
                    return buildReplay(rec);
                }
            } catch (AuditUnavailableException e) {
                log.warn("[访问网关] requestId={} 审计不可用，fail-closed 拒绝放行", request.requestId());
                return new AccessResponse(request.requestId(), false, DecisionReason.AUDIT_UNAVAILABLE,
                        "审计环节不可用，依据 fail-closed 策略拒绝访问，不返回任何受保护数据",
                        false, -1L, null, Map.of());
            }

            // 审计成功落库后才构建脱敏数据（最小必要，无直接标识）
            PatientRecord patient = patientStore.find(request.patientId()).orElseThrow();
            Map<String, Object> data = dataSanitizer.sanitize(patient, request.scope(), request.requesterId());
            String pseudonym = (String) data.get("pseudonym");
            log.info("[访问网关] requestId={} 判定依据: {} | 最终结论: ALLOWED seq={} pseudonym={}",
                    request.requestId(), rec.decisionBasis(), rec.seq(), pseudonym);
            return new AccessResponse(request.requestId(), true, DecisionReason.ALLOWED,
                    rec.decisionBasis(), false, rec.seq(), pseudonym, data);
        }
    }

    private AccessResponse denyAndAudit(AccessRequest request, AuthzResult decision) {
        try {
            AuditRecord rec = auditStore.append(candidateOf(request, decision, false)).record();
            return new AccessResponse(request.requestId(), false, rec.reason(), rec.decisionBasis(),
                    false, rec.seq(), null, Map.of());
        } catch (AuditUnavailableException e) {
            return failClosed(request, "审计环节不可用，依据 fail-closed 策略拒绝访问");
        }
    }

    /** 依据既有审计记录重放响应（不新增审计）。放行结论会重新确定性构建脱敏数据。 */
    private AccessResponse buildReplay(AuditRecord rec) {
        if (rec.allowed()) {
            PatientRecord patient = patientStore.find(rec.patientId()).orElseThrow();
            Map<String, Object> data = dataSanitizer.sanitize(patient, rec.scope(), rec.requesterId());
            String pseudonym = (String) data.get("pseudonym");
            log.info("[访问网关] 重放 requestId={} 结论 ALLOWED seq={}(replayed) pseudonym={}",
                    rec.requestId(), rec.seq(), pseudonym);
            return new AccessResponse(rec.requestId(), true, DecisionReason.ALLOWED,
                    rec.decisionBasis(), true, rec.seq(), pseudonym, data);
        }
        log.info("[访问网关] 重放 requestId={} 结论 {} seq={}(replayed)",
                rec.requestId(), rec.reason(), rec.seq());
        return new AccessResponse(rec.requestId(), false, rec.reason(), rec.decisionBasis(),
                true, rec.seq(), null, Map.of());
    }

    private AuditRecord candidateOf(AccessRequest request, AuthzResult decision, boolean replayed) {
        return new AuditRecord(0L, clock.instant(), request.requestId(), request.requesterId(),
                request.patientId(), request.scope(), request.purpose(), decision.allowed(),
                decision.reason(), decision.basis(), decision.grantId(), replayed);
    }

    private void validate(AccessRequest request) {
        if (request == null || request.requestId() == null || request.requestId().isBlank()
                || request.requesterId() == null || request.patientId() == null
                || request.scope() == null || request.purpose() == null) {
            throw new IllegalArgumentException("请求要素不完整：requestId/requesterId/patientId/scope/purpose 均必填");
        }
    }
}
