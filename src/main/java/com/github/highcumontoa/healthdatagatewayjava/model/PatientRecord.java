package com.github.highcumontoa.healthdatagatewayjava.model;

import java.util.List;

/** 受保护病历（含直接标识信息，未经脱敏不得对外）。 */
public record PatientRecord(
        String patientId,
        String name,
        String nationalId,
        String phone,
        int age,
        String gender,
        List<String> conditions,
        List<Medication> medications,
        List<LabResult> labResults
) {
    public record Medication(String name, String dosage) {}

    public record LabResult(String test, String value, String referenceRange) {}
}
