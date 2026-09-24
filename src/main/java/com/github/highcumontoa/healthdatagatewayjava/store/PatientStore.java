package com.github.highcumontoa.healthdatagatewayjava.store;

import com.github.highcumontoa.healthdatagatewayjava.model.PatientRecord;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** 内存病历存储（模拟受保护数据源）。 */
@Component
public class PatientStore {

    private final ConcurrentMap<String, PatientRecord> patients = new ConcurrentHashMap<>();

    public void save(PatientRecord record) {
        patients.put(record.patientId(), record);
    }

    public Optional<PatientRecord> find(String patientId) {
        return Optional.ofNullable(patients.get(patientId));
    }
}
