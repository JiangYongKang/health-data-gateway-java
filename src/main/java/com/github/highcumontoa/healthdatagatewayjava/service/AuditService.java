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
        return record(request, decision, patientPseudonym, null);
    }

    /**
     * 写入审计记录，可携带转授来源（叶子转授标识 / 根原始授权标识 / 链路深度）。
     *
     * @param delegationTrace 转授来源三元组；直接授权访问时传 null
     */
    public AuditRecord record(AccessRequest request, Decision decision, String patientPseudonym,
                              DelegationTrace delegationTrace) {
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
                decision.basis(),
                delegationTrace == null ? null : delegationTrace.delegationId(),
                delegationTrace == null ? null : delegationTrace.rootAuthorizationId(),
                delegationTrace == null ? 0 : delegationTrace.depth());
        return auditLog.append(record);
    }

    /** 审计记录中的转授来源：叶子转授 / 根原始授权 / 链路深度。 */
    public record DelegationTrace(String delegationId, String rootAuthorizationId, int depth) {
    }

    /**
     * 记录一笔转授授权事件（转授关系创建生效）。幂等键为 delegationId：
     * 重复提交回放首次记录，不产生第二条审计。
     */
    public AuditRecord recordDelegationGrant(
            com.github.highcumontoa.healthdatagatewayjava.domain.Delegation delegation,
            Decision decision) {
        if (!available.get()) {
            throw new IllegalStateException("audit subsystem unavailable");
        }
        AuditRecord record = new AuditRecord(
                delegation.delegationId(),
                delegation.delegateeId(),
                null,
                String.join(",", delegation.purposes()),
                delegation.scopes(),
                Instant.now(),
                Instant.now(),
                decision.allowed(),
                decision.denyReason(),
                decision.basis(),
                delegation.delegationId(),
                delegation.rootAuthorizationId(),
                delegation.depth(),
                AuditRecord.EVENT_DELEGATION_GRANT,
                delegation.delegatorId());
        return auditLog.append(record);
    }
}
