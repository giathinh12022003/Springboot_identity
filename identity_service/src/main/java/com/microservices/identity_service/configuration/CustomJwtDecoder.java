package com.microservices.identity_service.configuration;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import com.microservices.identity_service.entity.SigningKey;
import com.microservices.identity_service.service.KeyService;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;

import java.util.Date;

@Component
public class CustomJwtDecoder implements JwtDecoder {
    KeyService keyService;

    @Override
    public Jwt decode(String token) throws JwtException {

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 1. đọc kid từ header
            String kid = signedJWT.getHeader().getKeyID();

            SigningKey signingKey = keyService.getKeyByKid(kid);

            // 2. verify signature
            JWSVerifier verifier = new MACVerifier(signingKey.getSecret().getBytes());

            boolean verified = signedJWT.verify(verifier);

            if (!verified) {
                throw new JwtException("Invalid signature");
            }

            var claimsSet = signedJWT.getJWTClaimsSet();

            // 3. check expiry
            if (claimsSet.getExpirationTime().before(new Date())) {
                throw new JwtException("Token expired");
            }

            // 4. convert Spring Jwt
            return new Jwt(
                    token,
                    claimsSet.getIssueTime().toInstant(),
                    claimsSet.getExpirationTime().toInstant(),
                    signedJWT.getHeader().toJSONObject(),
                    claimsSet.getClaims());

        } catch (Exception e) {
            throw new JwtException("Invalid token", e);
        }
    }
    // public Jwt decode(String token) throws JwtException {
    // try {
    // SignedJWT signedJWT = SignedJWT.parse(token);

    // return new Jwt(token,
    // signedJWT.getJWTClaimsSet().getIssueTime().toInstant(),
    // signedJWT.getJWTClaimsSet().getExpirationTime().toInstant(),
    // signedJWT.getHeader().toJSONObject(),
    // signedJWT.getJWTClaimsSet().getClaims());

    // } catch (ParseException e) {
    // throw new JwtException("Invalid token");
    // }
    // }
}
