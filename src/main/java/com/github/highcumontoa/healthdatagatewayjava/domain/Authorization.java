package com.github.highcumontoa.healthdatagatewayjava.domain;

import java.time.Instant;
import java.util.Set;

/**
 * 一条授权记录：某请求方对某患者、在若干目的与数据范围内、于有效期内的访问许可。
 */
public record Authorization(
        String authorizationId,
        String requesterId,
        String patientId,
        Set<String> purposes,
        Set<String> scopes,
        Instant validFrom,
        Instant validUntil,
        boolean revoked) {

    public Authorization withRevoked() {
        return new Authorization(authorizationId, requesterId, patientId,
                purposes, scopes, validFrom, validUntil, true);
    }
}
