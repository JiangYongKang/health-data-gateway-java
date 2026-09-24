package com.github.highcumontoa.healthdatagatewayjava.model;

import java.time.Instant;
import java.util.Set;

/**
 * 授权：某请求方对某患者数据的访问授权，包含数据范围、使用目的与有效期。
 * 可变状态仅为“撤回”。
 */
public final class Grant {
    private final String grantId;
    private final String requesterId;
    private final String patientId;
    private final Set<DataScope> scopes;
    private final Set<Purpose> purposes;
    private final Instant validFrom;
    private final Instant validUntil;
    private volatile boolean revoked;

    public Grant(String grantId, String requesterId, String patientId,
                 Set<DataScope> scopes, Set<Purpose> purposes,
                 Instant validFrom, Instant validUntil, boolean revoked) {
        this.grantId = grantId;
        this.requesterId = requesterId;
        this.patientId = patientId;
        this.scopes = scopes;
        this.purposes = purposes;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
        this.revoked = revoked;
    }

    public String getGrantId() { return grantId; }
    public String getRequesterId() { return requesterId; }
    public String getPatientId() { return patientId; }
    public Set<DataScope> getScopes() { return scopes; }
    public Set<Purpose> getPurposes() { return purposes; }
    public Instant getValidFrom() { return validFrom; }
    public Instant getValidUntil() { return validUntil; }
    public boolean isRevoked() { return revoked; }
    public void markRevoked() { this.revoked = true; }
}
