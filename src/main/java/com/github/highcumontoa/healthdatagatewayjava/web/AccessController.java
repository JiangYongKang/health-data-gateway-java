package com.github.highcumontoa.healthdatagatewayjava.web;

import com.github.highcumontoa.healthdatagatewayjava.model.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.model.AccessResponse;
import com.github.highcumontoa.healthdatagatewayjava.service.AccessGatewayService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 健康数据访问接口。放行 200，拒绝（含审计 fail-closed）403，要素非法 400。 */
@RestController
@RequestMapping("/api/access")
public class AccessController {

    private final AccessGatewayService accessGatewayService;

    public AccessController(AccessGatewayService accessGatewayService) {
        this.accessGatewayService = accessGatewayService;
    }

    @PostMapping
    public ResponseEntity<AccessResponse> access(@RequestBody AccessRequest request) {
        AccessResponse response = accessGatewayService.access(request);
        return ResponseEntity
                .status(response.allowed() ? HttpStatus.OK : HttpStatus.FORBIDDEN)
                .body(response);
    }
}
