package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.Delegation;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
import com.github.highcumontoa.healthdatagatewayjava.store.DelegationStore;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * 授权判定：按数据范围、使用目的、有效期、撤回状态逐项校验，
 * 每一步都记录判定依据，保证结论可解释。
 * 除直接授权外，还会评估请求方作为被转授方持有的转授权限：
 * 转授必须自身有效且整条链路（到顶端原始授权）有效，否则级联失效，
 * 并给出与原始授权失效可区分的拒绝原因。
 */
@Service
public class AuthorizationService {

    private final AuthorizationStore authorizationStore;
    private final DelegationStore delegationStore;
    private final DelegationChainValidator chainValidator;

    public AuthorizationService(AuthorizationStore authorizationStore,
                                DelegationStore delegationStore,
                                DelegationChainValidator chainValidator) {
        this.authorizationStore = authorizationStore;
        this.delegationStore = delegationStore;
        this.chainValidator = chainValidator;
    }

    public Decision evaluate(AccessRequest request) {
        List<String> basis = new ArrayList<>();
        basis.add("request=" + request.requestId()
                + " requester=" + request.requesterId()
                + " patient=" + request.patientId()
                + " purpose=" + request.purpose()
                + " scopes=" + request.scopes());

        List<Authorization> candidates = authorizationStore
                .findByRequesterAndPatient(request.requesterId(), request.patientId());
        List<Delegation> delegationCandidates = delegationStore
                .findByDelegateeAndPatient(request.requesterId(), request.patientId());

        if (candidates.isEmpty() && delegationCandidates.isEmpty()) {
            basis.add("check=existence result=FAIL 无任何授权或转授记录");
            return Decision.deny(DenyReason.NO_AUTHORIZATION, basis);
        }
        if (!candidates.isEmpty()) {
            basis.add("check=existence result=PASS 命中授权 " + candidates.size() + " 条");
        }
        if (!delegationCandidates.isEmpty()) {
            basis.add("check=existence result=PASS 命中转授 " + delegationCandidates.size() + " 条");
        }

        Instant now = Instant.now();
        List<String> failureNotes = new ArrayList<>();

        // 1. 直接授权候选
        for (Authorization auth : candidates) {
            String tag = "auth=" + auth.authorizationId();
            if (auth.revoked()) {
                failureNotes.add(tag + " 已撤回");
                continue;
            }
            if (now.isBefore(auth.validFrom()) || !now.isBefore(auth.validUntil())) {
                failureNotes.add(tag + " 不在有效期 [" + auth.validFrom() + "," + auth.validUntil() + ")");
                continue;
            }
            if (!auth.purposes().contains(request.purpose())) {
                failureNotes.add(tag + " 目的 " + request.purpose() + " 未覆盖");
                continue;
            }
            if (!auth.scopes().containsAll(request.scopes())) {
                failureNotes.add(tag + " 数据范围 " + request.scopes() + " 超出授权 " + auth.scopes());
                continue;
            }
            basis.add("check=revoked result=PASS " + tag);
            basis.add("check=validity result=PASS 当前时刻 " + now + " 位于 ["
                    + auth.validFrom() + "," + auth.validUntil() + ")");
            basis.add("check=purpose result=PASS " + request.purpose() + " ∈ " + auth.purposes());
            basis.add("check=scope result=PASS " + request.scopes() + " ⊆ " + auth.scopes());
            return Decision.allow(basis);
        }

        // 2. 转授候选：自身有效 + 整条链路有效（级联收敛）+ 目的/范围覆盖
        List<DenyReason> delegationFailures = new ArrayList<>();
        for (Delegation d : delegationCandidates) {
            String tag = "delegation=" + d.delegationId();
            List<String> chainNotes = new ArrayList<>();
            Optional<DenyReason> chainInvalid = chainValidator.checkChain(d, now, chainNotes);
            if (chainInvalid.isPresent()) {
                failureNotes.add(tag + " 链路无效 reason=" + chainInvalid.get());
                chainNotes.forEach(n -> failureNotes.add("  " + n));
                delegationFailures.add(chainInvalid.get());
                continue;
            }
            if (!d.purposes().contains(request.purpose())) {
                failureNotes.add(tag + " 目的 " + request.purpose() + " 未覆盖 " + d.purposes());
                delegationFailures.add(DenyReason.PURPOSE_NOT_COVERED);
                continue;
            }
            if (!d.scopes().containsAll(request.scopes())) {
                failureNotes.add(tag + " 数据范围 " + request.scopes() + " 超出转授 " + d.scopes());
                delegationFailures.add(DenyReason.SCOPE_NOT_COVERED);
                continue;
            }
            basis.add("check=delegation-chain result=PASS " + tag + " depth=" + d.depth());
            chainNotes.forEach(n -> basis.add("  " + n));
            basis.add("check=purpose result=PASS " + request.purpose() + " ∈ " + d.purposes());
            basis.add("check=scope result=PASS " + request.scopes() + " ⊆ " + d.scopes());
            // 审计可追溯：记录该转授源自哪条原始授权、途经哪些持有者
            basis.add("trace 转授来源: delegation=" + d.delegationId()
                    + " root-auth=" + d.rootAuthorizationId()
                    + " chain=" + String.join(" -> ", d.holderChain()));
            return Decision.allow(basis);
        }

        // 3. 所有候选均不满足：归纳出可区分的拒绝原因
        basis.addAll(failureNotes);
        if (!candidates.isEmpty()) {
            return concludeFromDirectAuthorizations(request, candidates, now, basis);
        }
        return concludeFromDelegations(delegationFailures, basis);
    }

    /** 直接授权候选的拒绝原因归纳（保持原有行为不变）。 */
    private Decision concludeFromDirectAuthorizations(AccessRequest request,
                                                      List<Authorization> candidates,
                                                      Instant now, List<String> basis) {
        boolean anyRevoked = candidates.stream().anyMatch(Authorization::revoked);
        boolean allExpired = candidates.stream().allMatch(a ->
                !a.revoked() && (now.isBefore(a.validFrom()) || !now.isBefore(a.validUntil())));
        boolean anyPurposeMiss = candidates.stream().anyMatch(a ->
                !a.revoked() && !a.purposes().contains(request.purpose()));
        boolean anyScopeMiss = candidates.stream().anyMatch(a ->
                !a.revoked() && a.purposes().contains(request.purpose())
                        && !a.scopes().containsAll(request.scopes()));

        if (anyRevoked && candidates.stream().allMatch(Authorization::revoked)) {
            basis.add("conclude=REVOKED 全部授权已撤回");
            return Decision.deny(DenyReason.REVOKED, basis);
        }
        if (allExpired && !candidates.isEmpty()
                && candidates.stream().noneMatch(Authorization::revoked)) {
            basis.add("conclude=EXPIRED 授权已过有效期");
            return Decision.deny(DenyReason.EXPIRED, basis);
        }
        if (anyPurposeMiss) {
            basis.add("conclude=PURPOSE_NOT_COVERED 使用目的不在授权范围内");
            return Decision.deny(DenyReason.PURPOSE_NOT_COVERED, basis);
        }
        if (anyScopeMiss) {
            basis.add("conclude=SCOPE_NOT_COVERED 数据范围超出授权");
            return Decision.deny(DenyReason.SCOPE_NOT_COVERED, basis);
        }
        if (anyRevoked) {
            basis.add("conclude=REVOKED 授权已撤回");
            return Decision.deny(DenyReason.REVOKED, basis);
        }
        basis.add("conclude=EXPIRED 授权不在有效期内");
        return Decision.deny(DenyReason.EXPIRED, basis);
    }

    /** 转授候选的拒绝原因归纳：转授自身失效与原始授权级联失效可区分。 */
    private Decision concludeFromDelegations(List<DenyReason> delegationFailures, List<String> basis) {
        if (delegationFailures.contains(DenyReason.DELEGATION_REVOKED)) {
            basis.add("conclude=DELEGATION_REVOKED 转授权限已撤回");
            return Decision.deny(DenyReason.DELEGATION_REVOKED, basis);
        }
        if (delegationFailures.contains(DenyReason.PARENT_AUTHORIZATION_INVALID)) {
            basis.add("conclude=PARENT_AUTHORIZATION_INVALID 原始授权已失效，转授级联失效");
            return Decision.deny(DenyReason.PARENT_AUTHORIZATION_INVALID, basis);
        }
        if (delegationFailures.contains(DenyReason.DELEGATION_EXPIRED)) {
            basis.add("conclude=DELEGATION_EXPIRED 转授权限已过有效期");
            return Decision.deny(DenyReason.DELEGATION_EXPIRED, basis);
        }
        if (delegationFailures.contains(DenyReason.PURPOSE_NOT_COVERED)) {
            basis.add("conclude=PURPOSE_NOT_COVERED 使用目的不在转授范围内");
            return Decision.deny(DenyReason.PURPOSE_NOT_COVERED, basis);
        }
        basis.add("conclude=SCOPE_NOT_COVERED 数据范围超出转授范围");
        return Decision.deny(DenyReason.SCOPE_NOT_COVERED, basis);
    }
}
