package com.github.highcumontoa.healthdatagatewayjava.model;

import java.time.Instant;

/**
 * 不可变的访问审计记录。一旦写入，内容不再改变（append-only）。
 */
public record AuditRecord(
        long seq,
        Instant timestamp,
        String requestId,
        String requesterId,
        String patientId,
        DataScope scope,
        Purpose purpose,
        boolean allowed,
        DecisionReason reason,
        String decisionBasis,
        String grantId,
        boolean replayed
) {}
