package com.github.highcumontoa.healthdatagatewayjava.store;

import com.github.highcumontoa.healthdatagatewayjava.model.Grant;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** 内存授权存储。 */
@Component
public class GrantStore {

    private final ConcurrentMap<String, Grant> grants = new ConcurrentHashMap<>();

    /** 按授权ID分配的互斥锁，撤回与网关的“复核+写审计”共用同一把锁以保证线性一致。 */
    private final ConcurrentMap<String, Object> idLocks = new ConcurrentHashMap<>();

    public Object lockFor(String grantId) {
        return idLocks.computeIfAbsent(grantId, k -> new Object());
    }

    public void save(Grant grant) {
        grants.put(grant.getGrantId(), grant);
    }

    public Optional<Grant> find(String grantId) {
        return Optional.ofNullable(grants.get(grantId));
    }

    /** 查找请求方对该患者的授权（样例数据中每对主体至多一条，按 grantId 取最小者保证确定性）。 */
    public Optional<Grant> findActive(String requesterId, String patientId) {
        return grants.values().stream()
                .filter(g -> g.getRequesterId().equals(requesterId))
                .filter(g -> g.getPatientId().equals(patientId))
                .min(java.util.Comparator.comparing(Grant::getGrantId));
    }

    /** 撤回授权；若授权不存在返回 false，若已撤回则保持撤回状态返回 false。 */
    public boolean revoke(String grantId) {
        Grant grant = grants.get(grantId);
        if (grant == null) {
            return false;
        }
        synchronized (lockFor(grantId)) {
            if (grant.isRevoked()) {
                return false;
            }
            grant.markRevoked();
            return true;
        }
    }

    /** 清空全部授权（仅供测试间隔离使用，非业务接口）。 */
    public void reset() {
        grants.clear();
    }
}
