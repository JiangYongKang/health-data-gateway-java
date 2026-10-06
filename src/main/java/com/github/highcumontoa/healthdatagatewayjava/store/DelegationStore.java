package com.github.highcumontoa.healthdatagatewayjava.store;

import com.github.highcumontoa.healthdatagatewayjava.domain.Delegation;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 转授关系的内存存储，支持按标识/链路查询与原子撤回。
 * 撤回（包括基于原始授权撤回的级联撤回）对并发读取立即可见。
 */
@Repository
public class DelegationStore {

    private final ConcurrentHashMap<String, Delegation> byId = new ConcurrentHashMap<>();

    public void save(Delegation delegation) {
        byId.put(delegation.delegationId(), delegation);
    }

    /**
     * 幂等保存：同一 delegationId 仅首次写入生效。
     *
     * @return 实际生效的关系（重复提交时返回首次写入的关系，且 newlyCreated=false）
     */
    public SaveOutcome saveIfAbsent(Delegation delegation) {
        AtomicBoolean created = new AtomicBoolean(false);
        // merge 保证并发下只有一个写入生效，且能拿到最终值
        Delegation effective = byId.merge(delegation.delegationId(), delegation,
                (existing, incoming) -> existing);
        created.set(effective == delegation);
        return new SaveOutcome(effective, created.get());
    }

    public Optional<Delegation> findById(String delegationId) {
        return Optional.ofNullable(byId.get(delegationId));
    }

    public List<Delegation> findByRootAuthorization(String rootAuthorizationId) {
        return byId.values().stream()
                .filter(d -> d.rootAuthorizationId().equals(rootAuthorizationId))
                .toList();
    }

    /** 查询某机构作为被转授方、针对某患者当前持有的全部转授关系。 */
    public List<Delegation> findByDelegateeAndPatient(String delegateeId, String patientId) {
        return byId.values().stream()
                .filter(d -> d.delegateeId().equals(delegateeId)
                        && d.patientId().equals(patientId))
                .toList();
    }

    /** 撤回单条转授关系；返回撤回是否生效（存在且此前未撤回）。 */
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

    public record SaveOutcome(Delegation delegation, boolean newlyCreated) {
    }
}
