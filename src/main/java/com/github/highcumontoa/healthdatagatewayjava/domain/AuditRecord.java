package com.github.highcumontoa.healthdatagatewayjava.domain;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * 一条不可篡改的审计记录：请求要素 + 判定结论 + 判定依据。
 */
public record AuditRecord(
        String requestId,
        String requesterId,
        String patientPseudonym,
        String purpose,
        Set<String> scopes,
        Instant requestedAt,
        Instant auditedAt,
        boolean allowed,
        DenyReason denyReason,
        List<String> basis) {
}
