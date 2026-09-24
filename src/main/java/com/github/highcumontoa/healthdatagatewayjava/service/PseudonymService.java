package com.github.highcumontoa.healthdatagatewayjava.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * 替代标识服务。
 *
 * 语义：
 * - 同一请求方 + 同一患者：HMAC 确定性输出，替代标识稳定一致；
 * - 不同请求方：由于把 requesterId 纳入密钥材料（隔离域），同一患者的伪标识互不相同，
 *   且 HMAC 单向不可逆，无法据伪标识在请求方之间相互关联；
 * - 输出本身不含任何直接标识信息。
 */
@Service
public class PseudonymService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final HexFormat HEX = HexFormat.of();

    private final byte[] secret;

    public PseudonymService(@Value("${gateway.pseudonym.secret:default-secret-key}") String secret) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    public String pseudonym(String requesterId, String patientId) {
        try {
            // 请求方隔离：密钥由全局密钥与请求方身份共同派生
            Mac keyDerivation = Mac.getInstance(HMAC_ALGORITHM);
            keyDerivation.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            byte[] domainKey = keyDerivation.doFinal(("domain:" + requesterId).getBytes(StandardCharsets.UTF_8));

            // 患者标识在请求方隔离域内做确定性 HMAC
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(domainKey, HMAC_ALGORITHM));
            byte[] digest = mac.doFinal(patientId.getBytes(StandardCharsets.UTF_8));
            return "PSN-" + HEX.formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException("伪标识生成失败", e);
        }
    }
}
