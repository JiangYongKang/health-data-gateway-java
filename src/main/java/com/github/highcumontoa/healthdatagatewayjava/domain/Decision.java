package com.github.highcumontoa.healthdatagatewayjava.domain;

import java.util.List;

/**
 * 授权判定结论：放行或带原因的拒绝，附判定依据（逐项校验轨迹），保证可解释。
 */
public record Decision(boolean allowed, DenyReason denyReason, List<String> basis) {

    public static Decision allow(List<String> basis) {
        return new Decision(true, null, List.copyOf(basis));
    }

    public static Decision deny(DenyReason reason, List<String> basis) {
        return new Decision(false, reason, List.copyOf(basis));
    }
}
