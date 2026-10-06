package com.github.highcumontoa.healthdatagatewayjava.tests;

import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 转授 HTTP 接口冒烟测试：
 * 合法转授 200 并可追溯根原始授权；越权转授 403 + 可区分原因；
 * 凭转授关系访问 200 + 脱敏数据；重复转授提交幂等。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class DelegationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthorizationStore authorizationStore;

    @BeforeEach
    void seed() {
        authorizationStore.save(new Authorization(
                "AUTH-DEL-HTTP", "ORG-A", "PATIENT-001",
                Set.of("TREATMENT"), Set.of("DIAGNOSIS", "MEDICATION"),
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(30, ChronoUnit.DAYS), false));
    }

    @Test
    void createDelegation_thenDelegatedAccess_succeeds() throws Exception {
        String grantBody = """
                {"delegationId":"DEL-HTTP-1","delegatorId":"ORG-A","delegateeId":"ORG-B",
                 "patientId":"PATIENT-001","purpose":"TREATMENT","scopes":["DIAGNOSIS"],
                 "validFrom":"2026-10-06T01:00:00Z","validUntil":"2026-10-20T00:00:00Z",
                 "requestedAt":"2026-10-06T00:00:00Z"}
                """;
        System.out.println("==== HTTP 合法转授 ====");
        System.out.println("[输入] POST /api/gateway/delegations " + grantBody.strip());
        var grantResult = mockMvc.perform(post("/api/gateway/delegations")
                        .contentType(MediaType.APPLICATION_JSON).content(grantBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.delegationId").value("DEL-HTTP-1"))
                .andExpect(jsonPath("$.rootAuthorizationId").value("AUTH-DEL-HTTP"))
                .andExpect(jsonPath("$.depth").value(1))
                .andReturn();
        System.out.println("[最终结论] " + grantResult.getResponse().getContentAsString());

        // 被转授方以自己的身份访问
        String accessBody = """
                {"requestId":"REQ-DEL-HTTP-1","requesterId":"ORG-B","patientId":"PATIENT-001",
                 "purpose":"TREATMENT","scopes":["DIAGNOSIS"],"requestedAt":"2026-10-06T00:00:00Z",
                 "delegationId":"DEL-HTTP-1"}
                """;
        System.out.println("==== HTTP 凭转授访问 ====");
        System.out.println("[输入] POST /api/gateway/access " + accessBody.strip());
        var accessResult = mockMvc.perform(post("/api/gateway/access")
                        .contentType(MediaType.APPLICATION_JSON).content(accessBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.data.diagnosis").exists())
                .andExpect(jsonPath("$.data.name").doesNotExist())
                .andExpect(jsonPath("$.patientPseudonym").exists())
                .andReturn();
        System.out.println("[最终结论] " + accessResult.getResponse().getContentAsString());

        // 重复提交转授：幂等，仍 200 且回放同一条
        mockMvc.perform(post("/api/gateway/delegations")
                        .contentType(MediaType.APPLICATION_JSON).content(grantBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.delegationId").value("DEL-HTTP-1"));
    }

    @Test
    void overScopeDelegation_returns403WithDistinguishableReason() throws Exception {
        String body = """
                {"delegationId":"DEL-HTTP-2","delegatorId":"ORG-A","delegateeId":"ORG-B",
                 "patientId":"PATIENT-001","purpose":"TREATMENT",
                 "scopes":["DIAGNOSIS","LAB"],
                 "validFrom":"2026-10-06T01:00:00Z","validUntil":"2026-10-20T00:00:00Z",
                 "requestedAt":"2026-10-06T00:00:00Z"}
                """;
        System.out.println("==== HTTP 越权转授（范围超出） ====");
        System.out.println("[输入] POST /api/gateway/delegations " + body.strip());
        var result = mockMvc.perform(post("/api/gateway/delegations")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.denyReason").value("DELEGATION_SCOPE_EXCEEDED"))
                .andReturn();
        System.out.println("[最终结论] " + result.getResponse().getContentAsString());
    }
}
