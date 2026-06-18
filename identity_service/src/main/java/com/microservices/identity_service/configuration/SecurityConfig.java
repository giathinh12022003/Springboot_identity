package com.microservices.identity_service.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.microservices.identity_service.entity.SigningKey;
import com.microservices.identity_service.service.KeyService;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    KeyService keyService;

    private final String[] PUBLIC_ENDPOINTS = {
            "/api/v1/users/register",
            "/api/v1/auth/login",
            "/api/v1/auth/introspect",
            "/api/v1/auth/refresh-token",
            "/api/v1/auth/logout"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(request -> request.requestMatchers(HttpMethod.POST, PUBLIC_ENDPOINTS).permitAll()
                        .anyRequest().authenticated());

        httpSecurity.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(jwtDecoder())
                .jwtAuthenticationConverter(jwtAuthenticationConverter()))
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint()));
        httpSecurity.csrf(AbstractHttpConfigurer::disable);

        return httpSecurity.build();
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }

    // @Bean
    // JwtDecoder jwtDecoder() {
    // SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(),
    // "HS512");
    // return NimbusJwtDecoder
    // .withSecretKey(secretKeySpec)
    // .macAlgorithm(MacAlgorithm.HS512)
    // .build();
    // }

    @Bean
    JwtDecoder jwtDecoder() {
        return token -> {
            try {
                SignedJWT signedJWT = SignedJWT.parse(token);

                // đọc kid từ header
                String kid = signedJWT.getHeader().getKeyID();

                SigningKey signingKey = keyService.getKeyByKid(kid);

                // SecretKeySpec secretKeySpec = new
                // SecretKeySpec(signingKey.getSecret().getBytes(), "HS512");

                // NimbusJwtDecoder decoder = NimbusJwtDecoder
                // .withSecretKey(secretKeySpec)
                // .macAlgorithm(MacAlgorithm.HS512)
                // .build();

                byte[] keyBytes = Base64.getDecoder()
                        .decode(signingKey.getPublicKey());

                RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(
                                new X509EncodedKeySpec(keyBytes));

                NimbusJwtDecoder decoder = NimbusJwtDecoder
                        .withPublicKey(publicKey)
                        .signatureAlgorithm(SignatureAlgorithm.RS256)
                        .build();

                return decoder.decode(token);

            } catch (Exception e) {
                throw new JwtException("Invalid token");
            }
        };
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}
