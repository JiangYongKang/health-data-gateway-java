package com.github.highcumontoa.healthdatagatewayjava.api;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.service.GatewayService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    public GatewayController(GatewayService gatewayService) {
        this.gatewayService = gatewayService;
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
}
