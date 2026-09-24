package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.model.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.model.AuthzResult;
import com.github.highcumontoa.healthdatagatewayjava.model.DecisionReason;
import com.github.highcumontoa.healthdatagatewayjava.model.Grant;
import com.github.highcumontoa.healthdatagatewayjava.store.GrantStore;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * 授权判定：按固定优先级逐项校验——
 * 授权是否存在 -> 是否撤回 -> 是否生效 -> 是否过期 -> 数据范围 -> 使用目的。
 * 每个结论都附带人类可读的“判定依据”。
 */
@Service
public class AuthzEvaluator {

    private final GrantStore grantStore;
    private final Clock clock;

    public AuthzEvaluator(GrantStore grantStore, Clock clock) {
        this.grantStore = grantStore;
        this.clock = clock;
    }

    public AuthzResult evaluate(AccessRequest request) {
        Instant now = clock.instant();
        Optional<Grant> found = grantStore.findActive(request.requesterId(), request.patientId());
        if (found.isEmpty()) {
            return AuthzResult.deny(
                    DecisionReason.GRANT_NOT_FOUND,
                    "请求方[" + request.requesterId() + "]对患者[" + request.patientId()
                            + "]不存在任何授权");
        }
        Grant grant = found.get();

        if (grant.isRevoked()) {
            return AuthzResult.deny(
                    DecisionReason.REVOKED,
                    "授权[" + grant.getGrantId() + "]已被撤回，撤回后不得访问");
        }

        if (now.isBefore(grant.getValidFrom())) {
            return AuthzResult.deny(
                    DecisionReason.NOT_YET_VALID,
                    "授权[" + grant.getGrantId() + "]尚未生效：生效时间=" + grant.getValidFrom()
                            + "，当前时间=" + now);
        }

        if (now.isAfter(grant.getValidUntil())) {
            return AuthzResult.deny(
                    DecisionReason.EXPIRED,
                    "授权[" + grant.getGrantId() + "]已过期：失效时间=" + grant.getValidUntil()
                            + "，当前时间=" + now);
        }

        if (!grant.getScopes().contains(request.scope())) {
            return AuthzResult.deny(
                    DecisionReason.SCOPE_EXCEEDED,
                    "授权[" + grant.getGrantId() + "]数据范围=" + grant.getScopes()
                            + "，不包含请求范围[" + request.scope() + "]，超出最小必要授权");
        }

        if (!grant.getPurposes().contains(request.purpose())) {
            return AuthzResult.deny(
                    DecisionReason.PURPOSE_NOT_PERMITTED,
                    "授权[" + grant.getGrantId() + "]允许目的=" + grant.getPurposes()
                            + "，不包含请求目的[" + request.purpose() + "]");
        }

        return AuthzResult.allow(
                grant.getGrantId(),
                "授权[" + grant.getGrantId() + "]在有效期[" + grant.getValidFrom() + " ~ "
                        + grant.getValidUntil() + "]内，且范围[" + request.scope()
                        + "]与目的[" + request.purpose() + "]均获许可；当前时间=" + now);
    }
}
