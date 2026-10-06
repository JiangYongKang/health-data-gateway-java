package com.github.highcumontoa.healthdatagatewayjava.api;

import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.Delegation;
import com.github.highcumontoa.healthdatagatewayjava.domain.DelegationRequest;
import com.github.highcumontoa.healthdatagatewayjava.service.DelegationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 转授（委托）管理接口：持有有效授权的一方把部分权限转授给合作机构。
 * 成功返回 200 + 转授关系（含可追溯的根原始授权与链路深度）；
 * 越权转授返回 403 + 可区分的拒绝原因与判定依据。
 */
@RestController
@RequestMapping("/api/gateway")
public class DelegationController {

    public record DelegationResponse(boolean allowed,
                                     com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason denyReason,
                                     List<String> basis,
                                     String delegationId,
                                     String delegatorId,
                                     String delegateeId,
                                     String rootAuthorizationId,
                                     Integer depth) {
    }

    private final DelegationService delegationService;

    public DelegationController(DelegationService delegationService) {
        this.delegationService = delegationService;
    }

    @PostMapping("/delegations")
    public ResponseEntity<DelegationResponse> create(@RequestBody DelegationRequest request) {
        DelegationService.DelegationResult result = delegationService.createDelegation(request);
        Decision decision = result.decision();
        Delegation d = result.delegation();
        DelegationResponse body = new DelegationResponse(
                decision.allowed(),
                decision.denyReason(),
                decision.basis(),
                d == null ? null : d.delegationId(),
                d == null ? null : d.delegatorId(),
                d == null ? null : d.delegateeId(),
                d == null ? null : d.rootAuthorizationId(),
                d == null ? null : d.depth());
        return ResponseEntity
                .status(decision.allowed() ? HttpStatus.OK : HttpStatus.FORBIDDEN)
                .body(body);
    }
}
