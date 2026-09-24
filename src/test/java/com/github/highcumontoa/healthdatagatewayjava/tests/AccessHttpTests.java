package com.github.highcumontoa.healthdatagatewayjava.tests;

import com.github.highcumontoa.healthdatagatewayjava.config.SampleDataInitializer;
import com.github.highcumontoa.healthdatagatewayjava.service.AccessGatewayService;
import com.github.highcumontoa.healthdatagatewayjava.store.AuditStore;
import com.github.highcumontoa.healthdatagatewayjava.store.GrantStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** HTTP 接口端到端行为验证。 */
@SpringBootTest
@AutoConfigureMockMvc
class AccessHttpTests {

    private static final Logger log = LoggerFactory.getLogger(AccessHttpTests.class);

    @Autowired MockMvc mockMvc;
    @Autowired GrantStore grantStore;
    @Autowired AuditStore auditStore;
    @Autowired AccessGatewayService gateway;
    @Autowired SampleDataInitializer initializer;

    @BeforeEach
    void reset() throws Exception {
        auditStore.reset();
        grantStore.reset();
        gateway.setPreAuditHook(null);
        initializer.run();
    }

    private String json(String requestId, String org, String patient, String scope, String purpose) {
        return "{\"requestId\":\"%s\",\"requesterId\":\"%s\",\"patientId\":\"%s\",\"scope\":\"%s\",\"purpose\":\"%s\"}"
                .formatted(requestId, org, patient, scope, purpose);
    }

    @Test
    void httpAllowedReturnsSanitizedData() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("HTTP-1", "ORG-A", "P-1001", "LAB_RESULTS", "TREATMENT")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.reason").value("ALLOWED"))
                .andExpect(jsonPath("$.data.labResults").isArray())
                .andExpect(jsonPath("$.pseudonym").isString())
                .andReturn();
        String body = result.getResponse().getContentAsString();
        log.info("[HTTP正常] 响应: {}", body);
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("张三"));
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("110101"));
    }

    @Test
    void httpDeniedScopeHasDistinctReason() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("HTTP-2", "ORG-B", "P-1001", "LAB_RESULTS", "RESEARCH")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.reason").value("SCOPE_EXCEEDED"))
                .andReturn();
        log.info("[HTTP超范围] 响应: {}", result.getResponse().getContentAsString());
    }

    @Test
    void httpExpiredReason() throws Exception {
        mockMvc.perform(post("/api/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("HTTP-3", "ORG-C", "P-1001", "CONDITIONS", "TREATMENT")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("EXPIRED"));
    }

    @Test
    void httpRevokeThenAccessDeniedAndAuditQueryable() throws Exception {
        mockMvc.perform(post("/api/admin/grants/G-1001/revoke"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true));

        mockMvc.perform(post("/api/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("HTTP-4", "ORG-A", "P-1001", "CONDITIONS", "TREATMENT")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("REVOKED"));

        MvcResult audit = mockMvc.perform(get("/api/admin/audit"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].reason").value("REVOKED"))
                .andReturn();
        log.info("[HTTP撤回] 审计: {}", audit.getResponse().getContentAsString());
    }

    @Test
    void httpDuplicateRequestReplayed() throws Exception {
        String payload = json("HTTP-DUP", "ORG-A", "P-1001", "CONDITIONS", "TREATMENT");
        mockMvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.replayed").value(false));
        mockMvc.perform(post("/api/access").contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.replayed").value(true))
                .andExpect(jsonPath("$.auditSeq").value(1));
    }

    @Test
    void httpAuditDownThenForbidden() throws Exception {
        mockMvc.perform(post("/api/admin/audit/availability").param("available", "false"))
                .andExpect(status().isOk());
        try {
            MvcResult result = mockMvc.perform(post("/api/access")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json("HTTP-DOWN", "ORG-A", "P-1001", "CONDITIONS", "TREATMENT")))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.reason").value("AUDIT_UNAVAILABLE"))
                    .andReturn();
            log.info("[HTTP审计故障] 响应: {}", result.getResponse().getContentAsString());
        } finally {
            mockMvc.perform(post("/api/admin/audit/availability").param("available", "true"));
        }
    }

    @Test
    void httpInvalidRequestIs400() throws Exception {
        mockMvc.perform(post("/api/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"requestId\":\"HTTP-BAD\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_REQUEST"));
    }
}
