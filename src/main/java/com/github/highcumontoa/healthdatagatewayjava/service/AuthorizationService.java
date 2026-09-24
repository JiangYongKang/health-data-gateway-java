package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 授权判定：按数据范围、使用目的、有效期、撤回状态逐项校验，
 * 每一步都记录判定依据，保证结论可解释。
 */
@Service
public class AuthorizationService {

    private final AuthorizationStore authorizationStore;

    public AuthorizationService(AuthorizationStore authorizationStore) {
        this.authorizationStore = authorizationStore;
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
        if (candidates.isEmpty()) {
            basis.add("check=existence result=FAIL 无任何授权记录");
            return Decision.deny(DenyReason.NO_AUTHORIZATION, basis);
        }
        basis.add("check=existence result=PASS 命中授权 " + candidates.size() + " 条");

        Instant now = Instant.now();
        List<String> failureNotes = new ArrayList<>();
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

        // 所有候选授权均不满足：按优先级归纳出可区分的拒绝原因
        basis.addAll(failureNotes);
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
}
