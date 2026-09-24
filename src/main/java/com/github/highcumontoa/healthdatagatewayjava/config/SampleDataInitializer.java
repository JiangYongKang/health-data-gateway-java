package com.github.highcumontoa.healthdatagatewayjava.config;

import com.github.highcumontoa.healthdatagatewayjava.model.DataScope;
import com.github.highcumontoa.healthdatagatewayjava.model.Grant;
import com.github.highcumontoa.healthdatagatewayjava.model.PatientRecord;
import com.github.highcumontoa.healthdatagatewayjava.model.Purpose;
import com.github.highcumontoa.healthdatagatewayjava.store.GrantStore;
import com.github.highcumontoa.healthdatagatewayjava.store.PatientStore;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * 启动时装载内存样例数据。
 *
 * 患者：
 * - P-1001 张三 / P-1002 李四（均含直接标识，用于验证脱敏）
 *
 * 授权（requesterId -> patientId）：
 * - G-1001 机构A -> P-1001：四范围 + TREATMENT，长期有效（正常读取）
 * - G-1002 机构A -> P-1002：长期有效（用于验证不同请求方伪标识隔离，可由机构B对照）
 * - G-1003 机构B -> P-1001：仅 BASIC_PROFILE + RESEARCH（超范围/目的不符的边界）
 * - G-1004 机构C -> P-1001：已过期（EXPIRED）
 * - G-1005 机构D -> P-1001：尚未生效（NOT_YET_VALID）
 * - G-1006 机构E -> P-1001：已撤回（REVOKED）
 * - G-1007 机构A2 -> P-1002：用于与机构A对照同一患者伪标识不可关联
 */
@Component
public class SampleDataInitializer implements CommandLineRunner {

    private final GrantStore grantStore;
    private final PatientStore patientStore;

    public SampleDataInitializer(GrantStore grantStore, PatientStore patientStore) {
        this.grantStore = grantStore;
        this.patientStore = patientStore;
    }

    @Override
    public void run(String... args) {
        patientStore.save(new PatientRecord(
                "P-1001", "张三", "11010119900101001X", "138-0000-0001", 35, "男",
                List.of("2型糖尿病", "高血压"),
                List.of(new PatientRecord.Medication("二甲双胍", "500mg 每日两次"),
                        new PatientRecord.Medication("氨氯地平", "5mg 每日一次")),
                List.of(new PatientRecord.LabResult("糖化血红蛋白", "7.1%", "4.0% ~ 6.0%"),
                        new PatientRecord.LabResult("空腹血糖", "8.2 mmol/L", "3.9 ~ 6.1 mmol/L"))
        ));
        patientStore.save(new PatientRecord(
                "P-1002", "李四", "31010119850505002Y", "139-0000-0002", 41, "女",
                List.of("支气管哮喘"),
                List.of(new PatientRecord.Medication("布地奈德吸入剂", "200ug 每日两次")),
                List.of(new PatientRecord.LabResult("肺功能FEV1", "2.6 L", "> 2.5 L"))
        ));

        Instant past = Instant.parse("2020-01-01T00:00:00Z");
        Instant future = Instant.parse("2030-12-31T23:59:59Z");
        Set<DataScope> allScopes = Set.of(DataScope.BASIC_PROFILE, DataScope.CONDITIONS,
                DataScope.MEDICATIONS, DataScope.LAB_RESULTS);

        grantStore.save(new Grant("G-1001", "ORG-A", "P-1001",
                allScopes, Set.of(Purpose.TREATMENT), past, future, false));
        grantStore.save(new Grant("G-1002", "ORG-A", "P-1002",
                allScopes, Set.of(Purpose.TREATMENT, Purpose.RESEARCH), past, future, false));
        grantStore.save(new Grant("G-1003", "ORG-B", "P-1001",
                Set.of(DataScope.BASIC_PROFILE), Set.of(Purpose.RESEARCH), past, future, false));
        grantStore.save(new Grant("G-1004", "ORG-C", "P-1001",
                allScopes, Set.of(Purpose.TREATMENT),
                Instant.parse("2020-01-01T00:00:00Z"), Instant.parse("2020-12-31T23:59:59Z"), false));
        grantStore.save(new Grant("G-1005", "ORG-D", "P-1001",
                allScopes, Set.of(Purpose.TREATMENT),
                Instant.parse("2030-01-01T00:00:00Z"), future, false));
        grantStore.save(new Grant("G-1006", "ORG-E", "P-1001",
                allScopes, Set.of(Purpose.TREATMENT), past, future, true));
        grantStore.save(new Grant("G-1007", "ORG-A2", "P-1002",
                allScopes, Set.of(Purpose.TREATMENT), past, future, false));
    }
}
