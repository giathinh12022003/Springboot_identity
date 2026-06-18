package com.microservices.api_gateway.service;

import org.springframework.stereotype.Service;

import com.microservices.api_gateway.dto.request.IntrospectRequest;
import com.microservices.api_gateway.dto.response.ApiResponse;
import com.microservices.api_gateway.dto.response.IntrospectResponse;
import com.microservices.api_gateway.repository.IdentityClient;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class IdentityService {
    IdentityClient identityClient;

    public Mono<ApiResponse<IntrospectResponse>> introspect(String token){
        return identityClient.introspect(IntrospectRequest.builder()
                        .token(token)
                .build());
    }
}
