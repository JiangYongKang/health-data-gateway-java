package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.Delegation;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
import com.github.highcumontoa.healthdatagatewayjava.store.DelegationStore;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 转授链路校验：检查一笔转授从自身到顶端原始授权的完整链路在当前时刻是否有效。
 * 原始授权（或任一上级转授）被撤回或过期时，下游转授级联失效，
 * 并返回与“转授自身失效”可区分的拒绝原因。
 */
@Component
public class DelegationChainValidator {

    private final AuthorizationStore authorizationStore;
    private final DelegationStore delegationStore;

    public DelegationChainValidator(AuthorizationStore authorizationStore,
                                    DelegationStore delegationStore) {
        this.authorizationStore = authorizationStore;
        this.delegationStore = delegationStore;
    }

    /**
     * 校验转授 d 的完整链路（含 d 自身）。
     *
     * @return 空表示链路有效；否则返回可区分的拒绝原因，判定轨迹写入 notes
     */
    public Optional<DenyReason> checkChain(Delegation d, Instant now, List<String> notes) {
        // 1. 转授自身状态
        if (d.revoked()) {
            notes.add("delegation=" + d.delegationId() + " 转授自身已撤回");
            return Optional.of(DenyReason.DELEGATION_REVOKED);
        }
        if (now.isBefore(d.validFrom()) || !now.isBefore(d.validUntil())) {
            notes.add("delegation=" + d.delegationId() + " 转授自身不在有效期 ["
                    + d.validFrom() + "," + d.validUntil() + ")");
            return Optional.of(DenyReason.DELEGATION_EXPIRED);
        }

        // 2. 沿链向上逐级检查上级转授（级联收敛）
        String parentId = d.parentId();
        boolean parentIsDelegation = d.parentIsDelegation();
        while (parentIsDelegation) {
            Optional<Delegation> parent = delegationStore.findById(parentId);
            if (parent.isEmpty()) {
                notes.add("delegation=" + parentId + " 链路上级转授缺失");
                return Optional.of(DenyReason.PARENT_AUTHORIZATION_INVALID);
            }
            Delegation p = parent.get();
            if (p.revoked()) {
                notes.add("delegation=" + p.delegationId() + " 上级转授已撤回，本级级联失效");
                return Optional.of(DenyReason.PARENT_AUTHORIZATION_INVALID);
            }
            if (now.isBefore(p.validFrom()) || !now.isBefore(p.validUntil())) {
                notes.add("delegation=" + p.delegationId() + " 上级转授不在有效期，本级级联失效");
                return Optional.of(DenyReason.PARENT_AUTHORIZATION_INVALID);
            }
            parentId = p.parentId();
            parentIsDelegation = p.parentIsDelegation();
        }

        // 3. 链路顶端的原始授权
        Optional<Authorization> root = authorizationStore.findById(parentId);
        if (root.isEmpty()) {
            notes.add("auth=" + parentId + " 原始授权缺失");
            return Optional.of(DenyReason.PARENT_AUTHORIZATION_INVALID);
        }
        Authorization auth = root.get();
        if (auth.revoked()) {
            notes.add("auth=" + auth.authorizationId() + " 原始授权已撤回，下游转授级联失效");
            return Optional.of(DenyReason.PARENT_AUTHORIZATION_INVALID);
        }
        if (now.isBefore(auth.validFrom()) || !now.isBefore(auth.validUntil())) {
            notes.add("auth=" + auth.authorizationId() + " 原始授权已过有效期，下游转授级联失效");
            return Optional.of(DenyReason.PARENT_AUTHORIZATION_INVALID);
        }
        notes.add("chain=VALID 链路完整：delegation=" + d.delegationId()
                + " -> root-auth=" + auth.authorizationId());
        return Optional.empty();
    }
}
