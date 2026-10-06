package com.github.highcumontoa.healthdatagatewayjava.store;

import com.github.highcumontoa.healthdatagatewayjava.domain.Delegation;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 转授记录的内存存储：
 * - 按 delegationId 幂等保存（重复提交不产生第二条转授关系）；
 * - 支持原子撤回，撤回对并发读取立即可见。
 */
@Repository
public class DelegationStore {

    private final ConcurrentHashMap<String, Delegation> byId = new ConcurrentHashMap<>();

    /** 幂等保存：同一 delegationId 重复提交时返回已存在的记录，不产生重复转授。 */
    public Delegation saveIfAbsent(Delegation delegation) {
        Delegation existing = byId.putIfAbsent(delegation.delegationId(), delegation);
        return existing != null ? existing : delegation;
    }

    public Optional<Delegation> findById(String delegationId) {
        return Optional.ofNullable(byId.get(delegationId));
    }

    public List<Delegation> findByDelegateeAndPatient(String delegateeId, String patientId) {
        return byId.values().stream()
                .filter(d -> d.delegateeId().equals(delegateeId) && d.patientId().equals(patientId))
                .toList();
    }

    /** 撤回转授；返回撤回是否生效（存在且此前未撤回）。并发下仅一个调用者生效。 */
    public boolean revoke(String delegationId) {
        AtomicBoolean changed = new AtomicBoolean(false);
        byId.computeIfPresent(delegationId, (id, current) -> {
            if (current.revoked()) {
                return current;
            }
            changed.set(true);
            return current.withRevoked();
        });
        return changed.get();
    }
}
