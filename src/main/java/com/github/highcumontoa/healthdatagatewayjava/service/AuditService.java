package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.AuditRecord;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.store.AuditLog;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 审计服务：放行与拒绝都落审计；审计环节不可用时抛出异常，
 * 由网关将访问转为拒绝（审计不可用绝不允许放行）。
 */
@Service
public class AuditService {

    private final AuditLog auditLog;
    /** 模拟审计环节可用性开关（测试中可置为不可用）。 */
    private final AtomicBoolean available = new AtomicBoolean(true);

    public AuditService(AuditLog auditLog) {
        this.auditLog = auditLog;
    }

    public void setAvailable(boolean value) {
        available.set(value);
    }

    public boolean isAvailable() {
        return available.get();
    }

    /** 查询某请求是否已有审计结论（用于幂等去重）。 */
    public Optional<AuditRecord> findByRequestId(String requestId) {
        return auditLog.findByRequestId(requestId);
    }

    /** 写入审计记录；审计环节不可用时抛出 IllegalStateException。 */
    public AuditRecord record(AccessRequest request, Decision decision, String patientPseudonym) {
        if (!available.get()) {
            throw new IllegalStateException("audit subsystem unavailable");
        }
        AuditRecord record = new AuditRecord(
                request.requestId(),
                request.requesterId(),
                patientPseudonym,
                request.purpose(),
                request.scopes(),
                request.requestedAt(),
                Instant.now(),
                decision.allowed(),
                decision.denyReason(),
                decision.basis());
        return auditLog.append(record);
    }
}
