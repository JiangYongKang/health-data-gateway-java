package com.github.highcumontoa.healthdatagatewayjava.domain;

/**
 * 可区分的拒绝原因。
 */
public enum DenyReason {
    /** 请求方对该对象没有任何授权记录 */
    NO_AUTHORIZATION,
    /** 请求的使用目的不在授权范围内 */
    PURPOSE_NOT_COVERED,
    /** 请求的数据范围超出授权范围 */
    SCOPE_NOT_COVERED,
    /** 授权已过有效期 */
    EXPIRED,
    /** 授权已被撤回 */
    REVOKED,
    /** 审计环节不可用，按安全策略必须拒绝 */
    AUDIT_UNAVAILABLE,

    /* ===================== 授权转授（委托）相关原因 ===================== */

    /** 请求引用的转授关系不存在（或不属于本次请求方） */
    DELEGATION_NOT_FOUND,
    /** 请求方身份与转授关系中的被转授方不一致 */
    DELEGATION_PARTY_MISMATCH,
    /** 转授请求的数据范围超出其持有的原始授权/上游转授 */
    DELEGATION_SCOPE_EXCEEDED,
    /** 转授请求的使用目的超出其持有的原始授权/上游转授 */
    DELEGATION_PURPOSE_EXCEEDED,
    /** 转授有效期超过原始授权剩余有效期（或早于上游生效时间） */
    DELEGATION_DURATION_EXCEEDED,
    /** 转授链路深度超过上限 */
    DELEGATION_TOO_DEEP,
    /** 转授构成环路（委托绕回链路中已有的一方） */
    DELEGATION_CYCLE,
    /** 转授方自身并不持有可覆盖本次转授的有效授权 */
    DELEGATION_SOURCE_NOT_COVERED,
    /** 访问所依据的转授关系已被撤回（区别于原始授权撤回） */
    DELEGATION_REVOKED,
    /** 访问所依据的转授关系已过有效期（区别于原始授权过期） */
    DELEGATION_EXPIRED
}
