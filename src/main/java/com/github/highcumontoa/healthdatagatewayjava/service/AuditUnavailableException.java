package com.github.highcumontoa.healthdatagatewayjava.service;

/** 审计环节不可用时抛出，网关据此 fail-closed 拒绝访问。 */
public class AuditUnavailableException extends RuntimeException {

    public AuditUnavailableException(String message) {
        super(message);
    }

    public AuditUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
