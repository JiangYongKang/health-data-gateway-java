package com.github.highcumontoa.healthdatagatewayjava.api;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.DelegationRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.service.DelegationService;
import com.github.highcumontoa.healthdatagatewayjava.service.GatewayService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 对外 HTTP 接口：跨机构病历读取网关。
 * 放行返回 200 + 脱敏数据；拒绝返回 403 + 可区分的拒绝原因与判定依据。
 */
@RestController
@RequestMapping("/api/gateway")
public class GatewayController {

    public record AccessResponse(boolean allowed,
                                 DenyReason denyReason,
                                 List<String> basis,
                                 String patientPseudonym,
                                 Map<String, String> data) {
    }

    private final GatewayService gatewayService;
    private final DelegationService delegationService;

    public GatewayController(GatewayService gatewayService, DelegationService delegationService) {
        this.gatewayService = gatewayService;
        this.delegationService = delegationService;
    }

    @PostMapping("/access")
    public ResponseEntity<AccessResponse> access(@RequestBody AccessRequest request) {
        GatewayService.GatewayResponse result = gatewayService.handle(request);
        Decision decision = result.decision();
        AccessResponse body = new AccessResponse(
                decision.allowed(),
                decision.denyReason(),
                decision.basis(),
                result.patientPseudonym(),
                result.data());
        return ResponseEntity
                .status(decision.allowed() ? HttpStatus.OK : HttpStatus.FORBIDDEN)
                .body(body);
    }

    public record DelegationResponse(boolean allowed,
                                     DenyReason denyReason,
                                     List<String> basis,
                                     String delegationId,
                                     String rootAuthorizationId,
                                     Integer depth) {
    }

    /** 创建转授：持有有效授权的一方把部分权限转授给另一请求方。 */
    @PostMapping("/delegations")
    public ResponseEntity<DelegationResponse> delegate(@RequestBody DelegationRequest request) {
        DelegationService.DelegationOutcome outcome = delegationService.delegate(request);
        Decision decision = outcome.decision();
        DelegationResponse body = new DelegationResponse(
                decision.allowed(),
                decision.denyReason(),
                decision.basis(),
                outcome.delegation().map(d -> d.delegationId()).orElse(null),
                outcome.delegation().map(d -> d.rootAuthorizationId()).orElse(null),
                outcome.delegation().map(d -> d.depth()).orElse(null));
        return ResponseEntity
                .status(decision.allowed() ? HttpStatus.OK : HttpStatus.FORBIDDEN)
                .body(body);
    }

    /** 撤回转授：立即生效，对并发访问可见。 */
    @PostMapping("/delegations/{delegationId}/revoke")
    public ResponseEntity<Map<String, Object>> revokeDelegation(@PathVariable String delegationId) {
        boolean revoked = delegationService.revoke(delegationId);
        return ResponseEntity.ok(Map.of(
                "delegationId", delegationId,
                "revoked", revoked));
    }
}
