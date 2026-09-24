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
    AUDIT_UNAVAILABLE
}
