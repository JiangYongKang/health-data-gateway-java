package com.github.highcumontoa.healthdatagatewayjava.store;

import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 授权记录的内存存储，支持查询与撤回。撤回对并发读取立即可见。
 */
@Repository
public class AuthorizationStore {

    private final ConcurrentHashMap<String, Authorization> byId = new ConcurrentHashMap<>();

    public void save(Authorization authorization) {
        byId.put(authorization.authorizationId(), authorization);
    }

    public List<Authorization> findByRequesterAndPatient(String requesterId, String patientId) {
        return byId.values().stream()
                .filter(a -> a.requesterId().equals(requesterId) && a.patientId().equals(patientId))
                .toList();
    }

    public Optional<Authorization> findById(String authorizationId) {
        return Optional.ofNullable(byId.get(authorizationId));
    }

    /** 撤回授权；返回撤回是否生效（存在且此前未撤回）。并发下仅一个调用者生效。 */
    public boolean revoke(String authorizationId) {
        AtomicBoolean changed = new AtomicBoolean(false);
        byId.computeIfPresent(authorizationId, (id, current) -> {
            if (current.revoked()) {
                return current;
            }
            changed.set(true);
            return current.withRevoked();
        });
        return changed.get();
    }
}
