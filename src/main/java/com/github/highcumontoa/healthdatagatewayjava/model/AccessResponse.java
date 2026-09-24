package com.github.highcumontoa.healthdatagatewayjava.model;

import java.util.Map;

/** 网关访问响应：结论 + 可解释原因 + 脱敏后的最小必要数据。 */
public record AccessResponse(
        String requestId,
        boolean allowed,
        DecisionReason reason,
        String basis,
        boolean replayed,
        long auditSeq,
        String pseudonym,
        Map<String, Object> data
) {}
