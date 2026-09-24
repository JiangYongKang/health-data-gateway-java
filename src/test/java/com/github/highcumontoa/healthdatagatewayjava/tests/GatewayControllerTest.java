package com.github.highcumontoa.healthdatagatewayjava.tests;

import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * HTTP 接口冒烟测试：放行返回 200 + 脱敏数据；拒绝返回 403 + 可区分原因。
 */
@SpringBootTest
@AutoConfigureMockMvc
class GatewayControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthorizationStore authorizationStore;

    @BeforeEach
    void seed() {
        authorizationStore.save(new Authorization(
                "AUTH-HTTP", "ORG-A", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS"),
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(30, ChronoUnit.DAYS), false));
    }

    @Test
    void allowedRequest_returns200WithMaskedData() throws Exception {
        String body = """
                {"requestId":"REQ-HTTP-1","requesterId":"ORG-A","patientId":"PATIENT-001",
                 "purpose":"TREATMENT","scopes":["DIAGNOSIS"],"requestedAt":"2026-09-25T00:00:00Z"}
                """;
        System.out.println("==== HTTP 正常读取 ====");
        System.out.println("[输入] POST /api/gateway/access " + body.strip());
        var result = mockMvc.perform(post("/api/gateway/access")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.data.diagnosis").exists())
                .andExpect(jsonPath("$.data.name").doesNotExist())
                .andExpect(jsonPath("$.data.idCardNumber").doesNotExist())
                .andExpect(jsonPath("$.patientPseudonym").exists())
                .andReturn();
        System.out.println("[最终结论] " + result.getResponse().getContentAsString());
    }

    @Test
    void deniedRequest_returns403WithDistinguishableReason() throws Exception {
        String body = """
                {"requestId":"REQ-HTTP-2","requesterId":"ORG-C","patientId":"PATIENT-001",
                 "purpose":"TREATMENT","scopes":["DIAGNOSIS"],"requestedAt":"2026-09-25T00:00:00Z"}
                """;
        System.out.println("==== HTTP 无授权拒绝 ====");
        System.out.println("[输入] POST /api/gateway/access " + body.strip());
        var result = mockMvc.perform(post("/api/gateway/access")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.denyReason").value("NO_AUTHORIZATION"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andReturn();
        System.out.println("[最终结论] " + result.getResponse().getContentAsString());
    }
}
