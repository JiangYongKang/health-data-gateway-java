package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.AuditRecord;
import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.Delegation;
import com.github.highcumontoa.healthdatagatewayjava.domain.DelegationRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
import com.github.highcumontoa.healthdatagatewayjava.store.DelegationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 转授（委托）服务：把已有授权（或上级转授）的一部分权限转授给另一请求方。
 * 规则：
 * - 幂等：同一 delegationId 重复提交直接回放首次审计结论，不产生重复转授与重复审计；
 * - 转授方必须持有上级来源权限，且上级来源（含整条链路）当前有效；
 * - 转授的范围/目的/有效期不得超出上级来源；
 * - 转授链路深度不超过 MAX_DELEGATION_DEPTH，环状委托拒绝；
 * - 每笔转授落审计，basis 记录来源链路，可追溯到原始授权。
 */
@Service
public class DelegationService {

    private static final Logger log = LoggerFactory.getLogger(DelegationService.class);

    /** 转授链路深度上限：原始授权直接转授为第 1 层。 */
    public static final int MAX_DELEGATION_DEPTH = 3;

    public record DelegationOutcome(Decision decision, Optional<Delegation> delegation) {
    }

    private final AuthorizationStore authorizationStore;
    private final DelegationStore delegationStore;
    private final DelegationChainValidator chainValidator;
    private final AuditService auditService;
    private final PseudonymService pseudonymService;

    public DelegationService(AuthorizationStore authorizationStore,
                             DelegationStore delegationStore,
                             DelegationChainValidator chainValidator,
                             AuditService auditService,
                             PseudonymService pseudonymService) {
        this.authorizationStore = authorizationStore;
        this.delegationStore = delegationStore;
        this.chainValidator = chainValidator;
        this.auditService = auditService;
        this.pseudonymService = pseudonymService;
    }

    public DelegationOutcome delegate(DelegationRequest request) {
        // 1. 幂等去重：同一 delegationId 已有审计结论，直接回放，不产生重复转授与重复审计
        Optional<AuditRecord> existing = auditService.findByRequestId(request.delegationId());
        if (existing.isPresent()) {
            AuditRecord first = existing.get();
            List<String> basis = new ArrayList<>(first.basis());
            basis.add("idempotent-replay: delegationId=" + request.delegationId()
                    + " 已存在审计结论，不再重复转授");
            Decision replay = new Decision(first.allowed(), first.denyReason(), basis);
            log.info("[delegation] replay delegationId={} allowed={}",
                    request.delegationId(), replay.allowed());
            return new DelegationOutcome(replay, delegationStore.findById(request.delegationId()));
        }

        List<String> basis = new ArrayList<>();
        basis.add("delegation-request=" + request.delegationId()
                + " source=" + request.sourceId()
                + " delegator=" + request.delegatorId()
                + " delegatee=" + request.delegateeId()
                + " purposes=" + request.purposes()
                + " scopes=" + request.scopes()
                + " validity=[" + request.validFrom() + "," + request.validUntil() + ")");

        Instant now = Instant.now();

        // 2. 解析上级来源：原始授权或上级转授
        Optional<Authorization> sourceAuth = authorizationStore.findById(request.sourceId());
        Optional<Delegation> sourceDelegation = sourceAuth.isEmpty()
                ? delegationStore.findById(request.sourceId())
                : Optional.empty();
        if (sourceAuth.isEmpty() && sourceDelegation.isEmpty()) {
            basis.add("check=source result=FAIL 上级来源 " + request.sourceId() + " 不存在");
            return finish(request, Decision.deny(DenyReason.NO_AUTHORIZATION, basis), null);
        }

        String patientId;
        String sourceHolder;
        Set<String> sourcePurposes;
        Set<String> sourceScopes;
        Instant sourceValidFrom;
        Instant sourceValidUntil;
        int parentDepth;
        String rootAuthorizationId;
        List<String> parentChain;

        if (sourceAuth.isPresent()) {
            Authorization auth = sourceAuth.get();
            patientId = auth.patientId();
            sourceHolder = auth.requesterId();
            sourcePurposes = auth.purposes();
            sourceScopes = auth.scopes();
            sourceValidFrom = auth.validFrom();
            sourceValidUntil = auth.validUntil();
            parentDepth = 0;
            rootAuthorizationId = auth.authorizationId();
            parentChain = List.of(auth.requesterId());
            basis.add("check=source result=PASS 来源为原始授权 auth=" + auth.authorizationId());

            // 3a. 原始授权当前必须有效
            if (auth.revoked()) {
                basis.add("check=source-validity result=FAIL auth=" + auth.authorizationId() + " 已撤回");
                return finish(request, Decision.deny(DenyReason.REVOKED, basis), null);
            }
            if (now.isBefore(auth.validFrom()) || !now.isBefore(auth.validUntil())) {
                basis.add("check=source-validity result=FAIL auth=" + auth.authorizationId()
                        + " 不在有效期 [" + auth.validFrom() + "," + auth.validUntil() + ")");
                return finish(request, Decision.deny(DenyReason.EXPIRED, basis), null);
            }
            basis.add("check=source-validity result=PASS auth=" + auth.authorizationId() + " 当前有效");
        } else {
            Delegation parent = sourceDelegation.get();
            patientId = parent.patientId();
            sourceHolder = parent.delegateeId();
            sourcePurposes = parent.purposes();
            sourceScopes = parent.scopes();
            sourceValidFrom = parent.validFrom();
            sourceValidUntil = parent.validUntil();
            parentDepth = parent.depth();
            rootAuthorizationId = parent.rootAuthorizationId();
            parentChain = parent.holderChain();
            basis.add("check=source result=PASS 来源为上级转授 delegation=" + parent.delegationId()
                    + " depth=" + parent.depth());

            // 3b. 上级转授整条链路当前必须有效（含级联检查）
            Optional<DenyReason> chainInvalid = chainValidator.checkChain(parent, now, basis);
            if (chainInvalid.isPresent()) {
                basis.add("check=source-validity result=FAIL reason=" + chainInvalid.get());
                return finish(request, Decision.deny(chainInvalid.get(), basis), null);
            }
            basis.add("check=source-validity result=PASS 上级转授链路有效");
        }

        // 4. 转授方必须是上级来源的持有者
        if (!sourceHolder.equals(request.delegatorId())) {
            basis.add("check=holder result=FAIL delegator=" + request.delegatorId()
                    + " 不持有来源权限（持有者为 " + sourceHolder + "）");
            return finish(request, Decision.deny(DenyReason.NO_AUTHORIZATION, basis), null);
        }
        basis.add("check=holder result=PASS delegator=" + request.delegatorId() + " 持有来源权限");

        // 5. 深度上限
        int depth = parentDepth + 1;
        if (depth > MAX_DELEGATION_DEPTH) {
            basis.add("check=depth result=FAIL depth=" + depth
                    + " 超过上限 " + MAX_DELEGATION_DEPTH);
            return finish(request, Decision.deny(DenyReason.DELEGATION_DEPTH_EXCEEDED, basis), null);
        }
        basis.add("check=depth result=PASS depth=" + depth + " <= " + MAX_DELEGATION_DEPTH);

        // 6. 环状委托检测：被转授方不得已出现在链路持有者序列中
        if (parentChain.contains(request.delegateeId())) {
            basis.add("check=cycle result=FAIL delegatee=" + request.delegateeId()
                    + " 已在链路持有者序列 " + parentChain + " 中，构成环状委托");
            return finish(request, Decision.deny(DenyReason.DELEGATION_CYCLE, basis), null);
        }
        basis.add("check=cycle result=PASS delegatee=" + request.delegateeId()
                + " 不在链路持有者序列 " + parentChain + " 中");

        // 7. 越权检查：目的、范围、有效期均不得超出上级来源
        if (!sourcePurposes.containsAll(request.purposes())) {
            basis.add("check=purpose result=FAIL 转授目的 " + request.purposes()
                    + " 超出来源目的 " + sourcePurposes);
            return finish(request, Decision.deny(DenyReason.PURPOSE_NOT_COVERED, basis), null);
        }
        basis.add("check=purpose result=PASS " + request.purposes() + " ⊆ " + sourcePurposes);
        if (!sourceScopes.containsAll(request.scopes())) {
            basis.add("check=scope result=FAIL 转授范围 " + request.scopes()
                    + " 超出来源范围 " + sourceScopes);
            return finish(request, Decision.deny(DenyReason.SCOPE_NOT_COVERED, basis), null);
        }
        basis.add("check=scope result=PASS " + request.scopes() + " ⊆ " + sourceScopes);
        if (request.validFrom().isBefore(sourceValidFrom)
                || request.validUntil().isAfter(sourceValidUntil)
                || !request.validFrom().isBefore(request.validUntil())) {
            basis.add("check=validity result=FAIL 转授有效期 [" + request.validFrom() + ","
                    + request.validUntil() + ") 超出来源有效期 [" + sourceValidFrom + ","
                    + sourceValidUntil + ")");
            return finish(request, Decision.deny(DenyReason.DELEGATION_EXCEEDS_PARENT, basis), null);
        }
        if (!now.isBefore(request.validUntil())) {
            basis.add("check=validity result=FAIL 转授有效期已结束 validUntil=" + request.validUntil());
            return finish(request, Decision.deny(DenyReason.DELEGATION_EXCEEDS_PARENT, basis), null);
        }
        basis.add("check=validity result=PASS [" + request.validFrom() + ","
                + request.validUntil() + ") ⊆ [" + sourceValidFrom + "," + sourceValidUntil + ")");

        // 8. 创建转授（幂等保存：并发重复提交只生效一条）
        List<String> holderChain = new ArrayList<>(parentChain);
        holderChain.add(request.delegateeId());
        Delegation created = new Delegation(
                request.delegationId(),
                request.sourceId(),
                sourceDelegation.isPresent(),
                request.delegatorId(),
                request.delegateeId(),
                patientId,
                Set.copyOf(request.purposes()),
                Set.copyOf(request.scopes()),
                request.validFrom(),
                request.validUntil(),
                false,
                depth,
                rootAuthorizationId,
                List.copyOf(holderChain));
        Delegation effective = delegationStore.saveIfAbsent(created);
        basis.add("persist delegation=" + effective.delegationId()
                + " root-auth=" + effective.rootAuthorizationId()
                + " depth=" + effective.depth()
                + " chain=" + String.join(" -> ", effective.holderChain()));
        Decision allow = Decision.allow(basis);
        return finish(request, allow, effective);
    }

    /** 撤回转授；返回撤回是否生效。 */
    public boolean revoke(String delegationId) {
        boolean revoked = delegationStore.revoke(delegationId);
        log.info("[delegation] revoke delegationId={} changed={}", delegationId, revoked);
        return revoked;
    }

    /** 落审计并组装结果；审计不可用时按安全策略拒绝。 */
    private DelegationOutcome finish(DelegationRequest request, Decision decision, Delegation delegation) {
        String patientId = delegation != null ? delegation.patientId() : resolvePatientId(request);
        String pseudonym = patientId != null
                ? pseudonymService.pseudonymFor(request.delegatorId(), patientId)
                : null;
        AccessRequest auditView = new AccessRequest(
                request.delegationId(),
                request.delegatorId(),
                patientId != null ? patientId : "UNKNOWN",
                "DELEGATE:" + String.join(",", request.purposes()),
                request.scopes(),
                request.requestedAt());
        try {
            auditService.record(auditView, decision, pseudonym);
        } catch (IllegalStateException e) {
            List<String> basis = new ArrayList<>(decision.basis());
            basis.add("audit=UNAVAILABLE 审计环节不可用，按安全策略拒绝转授: " + e.getMessage());
            Decision denied = Decision.deny(DenyReason.AUDIT_UNAVAILABLE, basis);
            log.warn("[delegation] audit unavailable, deny delegationId={}", request.delegationId());
            return new DelegationOutcome(denied, Optional.empty());
        }
        log.info("[delegation] delegationId={} allowed={} reason={}",
                request.delegationId(), decision.allowed(), decision.denyReason());
        return new DelegationOutcome(decision, Optional.ofNullable(
                decision.allowed() ? delegation : null));
    }

    private String resolvePatientId(DelegationRequest request) {
        return authorizationStore.findById(request.sourceId())
                .map(Authorization::patientId)
                .or(() -> delegationStore.findById(request.sourceId()).map(Delegation::patientId))
                .orElse(null);
    }
}
