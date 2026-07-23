package com.microservices.identity_service.controller;

import java.text.ParseException;

import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.microservices.identity_service.dto.request.AuthenticationRequest;
import com.microservices.identity_service.dto.request.IntrospectRequest;
import com.microservices.identity_service.dto.response.ApiResponse;
import com.microservices.identity_service.dto.response.AuthenticationResponse;
import com.microservices.identity_service.dto.response.IntrospectResponse;
import com.microservices.identity_service.service.AuthenticationService;
import com.microservices.identity_service.utils.CookieUtil;
import com.nimbusds.jose.JOSEException;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationController {
    AuthenticationService authenticationService;
    CookieUtil cookieUtil;

    @PostMapping("/login")
    ApiResponse<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request,
            HttpServletResponse response) throws ParseException, JOSEException {
        var result = authenticationService.authenticate(request);

        cookieUtil.addRefreshTokenCookie(
                response,
                result.getRefreshToken());

        // log.info("refresh token: {}", result.getRefreshToken());

        result.setRefreshToken(null);
        return ApiResponse.<AuthenticationResponse>builder().result(result).build();
    }

    @PostMapping("/introspect")
    ApiResponse<IntrospectResponse> authenticate(@RequestBody IntrospectRequest request)
            throws ParseException, JOSEException {
        var result = authenticationService.introspect(request);
        return ApiResponse.<IntrospectResponse>builder().result(result).build();
    }

    @PostMapping("/refresh")
    ApiResponse<AuthenticationResponse> refresh(@CookieValue("refreshToken") String refreshToken,
            HttpServletResponse response)
            throws ParseException, JOSEException {

        AuthenticationResponse result = authenticationService.refreshToken(refreshToken);

        return ApiResponse.<AuthenticationResponse>builder().result(result).build();
    }

    @PostMapping("/logout")
    ApiResponse<Void> logout(@CookieValue(value = "refreshToken", required = false) String refreshToken,
            HttpServletResponse response) throws ParseException, JOSEException {

        if (refreshToken != null) {
            authenticationService.logout(refreshToken);
        }
        cookieUtil.clearRefreshTokenCookie(response);
        return ApiResponse.<Void>builder().build();
    }
}
