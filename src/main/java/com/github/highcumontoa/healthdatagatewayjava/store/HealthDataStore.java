package com.github.highcumontoa.healthdatagatewayjava.store;

import org.springframework.stereotype.Repository;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 模拟的受保护病历数据存储。原始数据含直接标识（姓名、证件号等），禁止直接外发。
 */
@Repository
public class HealthDataStore {

    /** 直接标识字段：任何情况下都不得出现在网关响应中。 */
    public static final Set<String> DIRECT_IDENTIFIERS =
            Set.of("name", "idCardNumber", "phoneNumber", "address");

    /** 数据范围 -> 该范围内的字段。 */
    private static final Map<String, Set<String>> SCOPE_FIELDS = Map.of(
            "DIAGNOSIS", Set.of("diagnosis", "diagnosisDate"),
            "MEDICATION", Set.of("medication", "dosage"),
            "LAB", Set.of("labResult", "labDate"));

    private final Map<String, Map<String, String>> patients = new LinkedHashMap<>();

    public HealthDataStore() {
        Map<String, String> p1 = new LinkedHashMap<>();
        p1.put("name", "张三");
        p1.put("idCardNumber", "110101199001011234");
        p1.put("phoneNumber", "13800000001");
        p1.put("address", "北京市海淀区某路1号");
        p1.put("diagnosis", "2型糖尿病");
        p1.put("diagnosisDate", "2025-11-03");
        p1.put("medication", "二甲双胍");
        p1.put("dosage", "500mg bid");
        p1.put("labResult", "HbA1c 7.2%");
        p1.put("labDate", "2026-08-15");
        patients.put("PATIENT-001", p1);

        Map<String, String> p2 = new LinkedHashMap<>();
        p2.put("name", "李四");
        p2.put("idCardNumber", "310104198505054321");
        p2.put("phoneNumber", "13900000002");
        p2.put("address", "上海市黄浦区某街2号");
        p2.put("diagnosis", "原发性高血压");
        p2.put("diagnosisDate", "2024-06-20");
        p2.put("medication", "氨氯地平");
        p2.put("dosage", "5mg qd");
        p2.put("labResult", "BP 138/86 mmHg");
        p2.put("labDate", "2026-09-01");
        patients.put("PATIENT-002", p2);
    }

    /**
     * 按数据范围读取患者原始病历字段（含直接标识，调用方必须脱敏后再外发）。
     *
     * @return 字段名 -> 字段值；患者不存在时返回 empty
     */
    public Optional<Map<String, String>> read(String patientId, Set<String> scopes) {
        Map<String, String> record = patients.get(patientId);
        if (record == null) {
            return Optional.empty();
        }
        Set<String> wanted = scopes.stream()
                .flatMap(s -> SCOPE_FIELDS.getOrDefault(s, Set.of()).stream())
                .collect(java.util.stream.Collectors.toSet());
        Map<String, String> result = new LinkedHashMap<>();
        record.forEach((k, v) -> {
            if (wanted.contains(k)) {
                result.put(k, v);
            }
        });
        return Optional.of(result);
    }
}
