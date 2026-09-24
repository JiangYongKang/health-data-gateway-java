package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.model.DataScope;
import com.github.highcumontoa.healthdatagatewayjava.model.PatientRecord;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 脱敏与最小必要裁剪。
 *
 * 保证：
 * - 响应中绝不出现 name / nationalId / phone 等直接标识，患者仅以伪标识出现；
 * - 仅输出被授权 scope 对应的字段，其余字段一律不带出（最小必要）。
 */
@Service
public class DataSanitizer {

    private final PseudonymService pseudonymService;

    public DataSanitizer(PseudonymService pseudonymService) {
        this.pseudonymService = pseudonymService;
    }

    public Map<String, Object> sanitize(PatientRecord record, DataScope scope, String requesterId) {
        Map<String, Object> out = new LinkedHashMap<>();
        // 直接标识字段（name/nationalId/phone/原始 patientId）一律不放入 out
        out.put("pseudonym", pseudonymService.pseudonym(requesterId, record.patientId()));
        out.put("scope", scope.name());

        switch (scope) {
            case BASIC_PROFILE -> {
                out.put("age", record.age());
                out.put("gender", record.gender());
            }
            case CONDITIONS -> out.put("conditions", List.copyOf(record.conditions()));
            case MEDICATIONS -> out.put("medications", List.copyOf(record.medications()));
            case LAB_RESULTS -> out.put("labResults", List.copyOf(record.labResults()));
        }
        return Map.copyOf(out);
    }
}
