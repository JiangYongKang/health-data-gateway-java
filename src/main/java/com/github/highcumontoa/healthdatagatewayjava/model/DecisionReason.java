package com.github.highcumontoa.healthdatagatewayjava.model;

/** 授权判定的可区分结论（放行与各类拒绝原因）。 */
public enum DecisionReason {
    ALLOWED,
    GRANT_NOT_FOUND,
    SCOPE_EXCEEDED,
    PURPOSE_NOT_PERMITTED,
    NOT_YET_VALID,
    EXPIRED,
    REVOKED,
    AUDIT_UNAVAILABLE
}
