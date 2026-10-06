package com.github.highcumontoa.healthdatagatewayjava.domain;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * 一条转授（委托）记录：持有授权的一方把自己权限的一部分转授给另一请求方。
 * 每笔转授都可沿 parentId 追溯到原始授权 rootAuthorizationId。
 *
 * @param delegationId       转授标识（幂等键，由转授方生成）
 * @param parentId           上级来源标识：原始授权 ID 或上级转授 ID
 * @param parentIsDelegation 上级来源是否为转授（false 表示直接源自原始授权）
 * @param delegatorId        转授方（必须持有上级来源权限）
 * @param delegateeId        被转授方（以自己的身份读取数据）
 * @param patientId          受保护对象（患者）标识
 * @param purposes           转授的使用目的（不得超出上级来源）
 * @param scopes             转授的数据范围（不得超出上级来源）
 * @param validFrom          生效时间
 * @param validUntil         失效时间（不得晚于上级来源的失效时间）
 * @param revoked            是否已撤回
 * @param depth              转授深度：直接源自原始授权为 1，逐层递增
 * @param rootAuthorizationId 链路顶端的原始授权 ID（追溯来源）
 * @param holderChain        链路持有者序列（根授权请求方到本转授的被转授方），用于环检测
 */
public record Delegation(
        String delegationId,
        String parentId,
        boolean parentIsDelegation,
        String delegatorId,
        String delegateeId,
        String patientId,
        Set<String> purposes,
        Set<String> scopes,
        Instant validFrom,
        Instant validUntil,
        boolean revoked,
        int depth,
        String rootAuthorizationId,
        List<String> holderChain) {

    public Delegation withRevoked() {
        return new Delegation(delegationId, parentId, parentIsDelegation, delegatorId, delegateeId,
                patientId, purposes, scopes, validFrom, validUntil, true,
                depth, rootAuthorizationId, holderChain);
    }
}
