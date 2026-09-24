package com.github.highcumontoa.healthdatagatewayjava.store;

import com.github.highcumontoa.healthdatagatewayjava.model.AuditRecord;
import com.github.highcumontoa.healthdatagatewayjava.service.AuditUnavailableException;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 只追加（append-only）的内存审计存储。
 *
 * 语义：
 * - append 对同一 requestId 原子地“无则写入、有则返回既有记录”，保证不产生重复审计；
 * - 记录一旦写入，本类不提供任何修改/删除入口（已写入记录不会被静默改写）；
 * - available=false 模拟审计环节故障，append 直接 fail-closed 抛异常。
 */
@Component
public class AuditStore {

    private final CopyOnWriteArrayList<AuditRecord> records = new CopyOnWriteArrayList<>();
    private final ConcurrentMap<String, AuditRecord> byRequestId = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong(0);
    private final AtomicBoolean available = new AtomicBoolean(true);
    private final Clock clock;

    public AuditStore(Clock clock) {
        this.clock = clock;
    }

    public void setAvailable(boolean value) {
        available.set(value);
    }

    public boolean isAvailable() {
        return available.get();
    }

    /** append 的结果：最终记录 + 是否本次新写入（false 表示命中了既有审计记录）。 */
    public record AppendResult(AuditRecord record, boolean created) {}

    /**
     * 原子写入：审计不可用时抛出 AuditUnavailableException；
     * requestId 已存在时返回既有记录而不新增（created=false）；
     * 否则分配单调序号与时间戳并追加，返回最终记录（created=true）。
     */
    public AppendResult append(AuditRecord candidate) {
        synchronized (records) {
            if (!available.get()) {
                throw new AuditUnavailableException("审计环节不可用，依据 fail-closed 策略拒绝写入");
            }
            AuditRecord existing = byRequestId.get(candidate.requestId());
            if (existing != null) {
                return new AppendResult(existing, false);
            }
            AuditRecord stored = new AuditRecord(
                    sequence.incrementAndGet(),
                    clock.instant(),
                    candidate.requestId(),
                    candidate.requesterId(),
                    candidate.patientId(),
                    candidate.scope(),
                    candidate.purpose(),
                    candidate.allowed(),
                    candidate.reason(),
                    candidate.decisionBasis(),
                    candidate.grantId(),
                    false
            );
            records.add(stored);
            byRequestId.put(stored.requestId(), stored);
            return new AppendResult(stored, true);
        }
    }

    public Optional<AuditRecord> findByRequestId(String requestId) {
        return Optional.ofNullable(byRequestId.get(requestId));
    }

    /** 返回审计记录的不可变快照。 */
    public List<AuditRecord> all() {
        return List.copyOf(records);
    }

    /** 清空全部记录并恢复可用性（仅供测试间隔离使用，非业务接口）。 */
    public void reset() {
        synchronized (records) {
            records.clear();
            byRequestId.clear();
            sequence.set(0L);
            available.set(true);
        }
    }
}
