package com.github.highcumontoa.healthdatagatewayjava.store;

import com.github.highcumontoa.healthdatagatewayjava.domain.AuditRecord;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 追加式审计日志：
 * - 记录一旦写入不得被后续操作静默改写（只提供 append / 查询，不提供更新与删除）；
 * - 同一 requestId 幂等：重复追加返回首次写入的记录，不产生第二条。
 */
@Repository
public class AuditLog {

    private final ConcurrentHashMap<String, AuditRecord> byRequestId = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<AuditRecord> ordered = new CopyOnWriteArrayList<>();

    /**
     * 追加一条审计记录。同一 requestId 重复追加时不得产生第二条记录。
     *
     * @return 实际生效的记录（重复提交时返回首次写入的记录）
     */
    public AuditRecord append(AuditRecord record) {
        AuditRecord existing = byRequestId.putIfAbsent(record.requestId(), record);
        if (existing != null) {
            return existing;
        }
        ordered.add(record);
        return record;
    }

    public Optional<AuditRecord> findByRequestId(String requestId) {
        return Optional.ofNullable(byRequestId.get(requestId));
    }

    public List<AuditRecord> findAll() {
        return List.copyOf(ordered);
    }
}
