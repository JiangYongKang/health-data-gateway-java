package com.github.highcumontoa.healthdatagatewayjava.domain;

import java.time.Instant;
import java.util.Set;

/**
 * 一次转授请求：把 sourceId 指向的权限（原始授权或上级转授）的一部分转授给 delegateeId。
 *
 * @param delegationId 转授标识（幂等键，重复提交不得产生重复转授与重复审计）
 * @param sourceId     上级来源标识：原始授权 ID 或上级转授 ID
 * @param delegatorId  转授方（必须是上级来源的持有者）
 * @param delegateeId  被转授方
 * @param purposes     转授的使用目的（必须 ⊆ 上级来源目的）
 * @param scopes       转授的数据范围（必须 ⊆ 上级来源范围）
 * @param validFrom    生效时间
 * @param validUntil   失效时间（必须 ≤ 上级来源失效时间）
 * @param requestedAt  请求时间
 */
public record DelegationRequest(
        String delegationId,
        String sourceId,
        String delegatorId,
        String delegateeId,
        Set<String> purposes,
        Set<String> scopes,
        Instant validFrom,
        Instant validUntil,
        Instant requestedAt) {
}
