package com.github.highcumontoa.healthdatagatewayjava.domain;

import java.time.Instant;
import java.util.Set;

/**
 * 一笔授权转授（委托）关系：转授方把自己所持有效授权（原始授权或上游转授）的一部分，
 * 在不超过上游约束的前提下转授给被转授方，由被转授方以自己的身份读取数据。
 *
 * @param delegationId      转授关系标识，同时作为重复提交的幂等键
 * @param delegatorId       转授方（当前持有授权的一方）
 * @param delegateeId       被转授方（凭此关系以自己身份访问的一方）
 * @param patientId         受保护对象
 * @param purposes          转授的使用目的（必须为上游目的集合的子集）
 * @param scopes            转授的数据范围（必须为上游范围的子集）
 * @param validFrom         转授生效时间（不得早于上游生效时间）
 * @param validUntil        转授失效时间（不得晚于原始授权剩余有效期）
 * @param parentDelegationId 上游转授关系标识；转授方直接持有的是原始授权时为 null
 * @param rootAuthorizationId 链路源头的原始授权标识，每一笔转授都可追溯到它
 * @param depth             链路深度：原始授权为 0，从原始授权直接转授为 1，依次递增
 * @param revoked           转授关系是否已被撤回
 */
public record Delegation(
        String delegationId,
        String delegatorId,
        String delegateeId,
        String patientId,
        Set<String> purposes,
        Set<String> scopes,
        Instant validFrom,
        Instant validUntil,
        String parentDelegationId,
        String rootAuthorizationId,
        int depth,
        boolean revoked) {

    public Delegation withRevoked() {
        return new Delegation(delegationId, delegatorId, delegateeId, patientId,
                purposes, scopes, validFrom, validUntil,
                parentDelegationId, rootAuthorizationId, depth, true);
    }
}
