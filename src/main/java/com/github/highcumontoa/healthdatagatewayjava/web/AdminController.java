package com.github.highcumontoa.healthdatagatewayjava.web;

import com.github.highcumontoa.healthdatagatewayjava.model.AuditRecord;
import com.github.highcumontoa.healthdatagatewayjava.store.AuditStore;
import com.github.highcumontoa.healthdatagatewayjava.store.GrantStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** 管理接口：撤回授权、审计查询、模拟审计故障。 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final GrantStore grantStore;
    private final AuditStore auditStore;

    public AdminController(GrantStore grantStore, AuditStore auditStore) {
        this.grantStore = grantStore;
        this.auditStore = auditStore;
    }

    @PostMapping("/grants/{grantId}/revoke")
    public Map<String, Object> revoke(@PathVariable String grantId) {
        boolean changed = grantStore.revoke(grantId);
        return Map.of("grantId", grantId, "revoked", changed);
    }

    @GetMapping("/audit")
    public List<AuditRecord> audit() {
        return auditStore.all();
    }

    @PostMapping("/audit/availability")
    public Map<String, Object> setAuditAvailability(@RequestParam boolean available) {
        auditStore.setAvailable(available);
        return Map.of("auditAvailable", available);
    }
}
