package com.github.highcumontoa.healthdatagatewayjava.domain;

import java.time.Instant;
import java.util.Set;

/**
 * 一次转授申请：由 delegatorId 把对 patientId 的部分权限转授给 delegateeId。
 *
 * @param delegationId 转授关系标识（幂等键）；重复提交相同 delegationId 不得产生重复关系
 * @param delegatorId  转授方，必须持有可覆盖本次转授内容的有效授权（原始授权或上游转授）
 * @param delegateeId  被转授方
 * @param patientId    受保护对象
 * @param purpose      转授的使用目的
 * @param scopes       转授的数据范围
 * @param validFrom    期望生效时间
 * @param validUntil   期望失效时间
 * @param requestedAt  申请时间
 */
public record DelegationRequest(
        String delegationId,
        String delegatorId,
        String delegateeId,
        String patientId,
        String purpose,
        Set<String> scopes,
        Instant validFrom,
        Instant validUntil,
        Instant requestedAt) {
}
