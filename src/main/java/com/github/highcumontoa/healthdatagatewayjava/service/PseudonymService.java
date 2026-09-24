package com.github.highcumontoa.healthdatagatewayjava.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * 替代标识服务：
 * - 同一请求方对同一患者的替代标识保持稳定（确定性 HMAC）；
 * - 不同请求方之间不可相互关联（每个请求方派生独立密钥，
 *   由本地随机主密钥经 SHA-256 派生，外部无法跨请求方反推同一患者）。
 */
@Service
public class PseudonymService {

    private final byte[] masterKey;

    public PseudonymService() {
        // 本地随机主密钥，进程内稳定，不依赖任何外部服务
        masterKey = new byte[32];
        new java.security.SecureRandom().nextBytes(masterKey);
    }

    public String pseudonymFor(String requesterId, String patientId) {
        try {
            byte[] requesterKey = MessageDigest.getInstance("SHA-256")
                    .digest((requesterId + "|" + HexFormat.of().formatHex(masterKey))
                            .getBytes(StandardCharsets.UTF_8));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(requesterKey, "HmacSHA256"));
            byte[] out = mac.doFinal(patientId.getBytes(StandardCharsets.UTF_8));
            return "PSN-" + HexFormat.of().formatHex(out, 0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("pseudonym derivation failed", e);
        }
    }
}
