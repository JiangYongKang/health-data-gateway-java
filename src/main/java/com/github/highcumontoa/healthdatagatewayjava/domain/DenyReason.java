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
    /** 转授权限本身已被撤回（区别于原始授权失效） */
    DELEGATION_REVOKED,
    /** 转授权限本身已过有效期（区别于原始授权失效） */
    DELEGATION_EXPIRED,
    /** 转授链路顶端的原始授权已失效（撤回或过期），转授级联失效 */
    PARENT_AUTHORIZATION_INVALID,
    /** 转授的范围/目的/有效期超出上级来源 */
    DELEGATION_EXCEEDS_PARENT,
    /** 转授链路深度超过上限 */
    DELEGATION_DEPTH_EXCEEDED,
    /** 转授构成环状委托 */
    DELEGATION_CYCLE
}
