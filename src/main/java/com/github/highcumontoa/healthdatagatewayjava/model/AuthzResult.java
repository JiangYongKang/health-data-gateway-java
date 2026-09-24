package com.github.highcumontoa.healthdatagatewayjava.model;

/** 授权判定结论及依据。 */
public record AuthzResult(boolean allowed, DecisionReason reason, String grantId, String basis) {

    public static AuthzResult deny(DecisionReason reason, String basis) {
        return new AuthzResult(false, reason, null, basis);
    }

    public static AuthzResult allow(String grantId, String basis) {
        return new AuthzResult(true, DecisionReason.ALLOWED, grantId, basis);
    }
}
