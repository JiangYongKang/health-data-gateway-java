package com.github.highcumontoa.healthdatagatewayjava.domain;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * 一条不可篡改的审计记录：请求要素 + 判定结论 + 判定依据。
 *
 * <p>转授访问时，{@code delegationId}/{@code rootAuthorizationId}/{@code delegationDepth}
 * 体现本次访问所依据的转授权限来源（每一笔转授都可追溯到源头原始授权）；
 * 直接授权访问时三者为 null/0。
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
        List<String> basis,
        String delegationId,
        String rootAuthorizationId,
        int delegationDepth,
        String eventType,
        String delegatorId) {

    /** 访问事件（直接授权或转授读取）。 */
    public static final String EVENT_ACCESS = "ACCESS";
    /** 转授授权事件（一笔转授关系创建生效）。 */
    public static final String EVENT_DELEGATION_GRANT = "DELEGATION_GRANT";

    /** 直接授权访问的兼容构造函数（无转授来源）。 */
    public AuditRecord(String requestId, String requesterId, String patientPseudonym,
                       String purpose, Set<String> scopes, Instant requestedAt,
                       Instant auditedAt, boolean allowed, DenyReason denyReason,
                       List<String> basis) {
        this(requestId, requesterId, patientPseudonym, purpose, scopes, requestedAt,
                auditedAt, allowed, denyReason, basis, null, null, 0, EVENT_ACCESS, null);
    }

    /** 转授访问事件的构造函数（带转授来源，事件类型为访问）。 */
    public AuditRecord(String requestId, String requesterId, String patientPseudonym,
                       String purpose, Set<String> scopes, Instant requestedAt,
                       Instant auditedAt, boolean allowed, DenyReason denyReason,
                       List<String> basis,
                       String delegationId, String rootAuthorizationId, int delegationDepth) {
        this(requestId, requesterId, patientPseudonym, purpose, scopes, requestedAt,
                auditedAt, allowed, denyReason, basis,
                delegationId, rootAuthorizationId, delegationDepth, EVENT_ACCESS, null);
    }
}
