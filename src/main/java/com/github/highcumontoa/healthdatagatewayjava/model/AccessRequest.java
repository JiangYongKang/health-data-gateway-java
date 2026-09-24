package com.github.highcumontoa.healthdatagatewayjava.model;

/** 一次受保护数据访问请求的要素。 */
public record AccessRequest(
        String requestId,
        String requesterId,
        String patientId,
        DataScope scope,
        Purpose purpose
) {}
