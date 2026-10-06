package com.github.highcumontoa.healthdatagatewayjava.domain;

import java.time.Instant;
import java.util.Set;

/**
 * 一次跨机构读取受保护病历数据的访问请求。
 *
 * @param requestId  请求方生成的幂等标识，重复提交同一 requestId 不得产生重复审计
 * @param requesterId 请求方（机构）标识
 * @param patientId  受保护对象（患者）标识
 * @param purpose    使用目的，例如 TREATMENT / RESEARCH
 * @param scopes     请求的数据范围，例如 DIAGNOSIS / MEDICATION / LAB
 * @param requestedAt 请求时间
 * @param delegationId 本次访问所依据的转授关系标识；直接使用自有授权访问时为 null
 */
public record AccessRequest(
        String requestId,
        String requesterId,
        String patientId,
        String purpose,
        Set<String> scopes,
        Instant requestedAt,
        String delegationId) {

    /** 直接授权访问的兼容构造函数（无转授关系）。 */
    public AccessRequest(String requestId, String requesterId, String patientId,
                         String purpose, Set<String> scopes, Instant requestedAt) {
        this(requestId, requesterId, patientId, purpose, scopes, requestedAt, null);
    }

    public boolean viaDelegation() {
        return delegationId != null;
    }
}
