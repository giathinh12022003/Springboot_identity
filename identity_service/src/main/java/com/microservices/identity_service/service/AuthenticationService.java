package com.microservices.identity_service.service;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.StringJoiner;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import com.microservices.identity_service.dto.request.AuthenticationRequest;
import com.microservices.identity_service.dto.request.IntrospectRequest;
import com.microservices.identity_service.dto.response.AuthenticationResponse;
import com.microservices.identity_service.dto.response.IntrospectResponse;
import com.microservices.identity_service.entity.InvalidatedToken;
import com.microservices.identity_service.entity.SigningKey;
import com.microservices.identity_service.entity.User;
import com.microservices.identity_service.exception.AppException;
import com.microservices.identity_service.exception.ErrorCode;
import com.microservices.identity_service.repository.InvalidatedTokenRepository;
import com.microservices.identity_service.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationService {
    UserRepository userRepository;
    InvalidatedTokenRepository invalidatedTokenRepository;
    KeyService keyService;

    @NonFinal
    @Value("${jwt.valid-duration}")
    protected long VALID_DURATION;

    @NonFinal
    @Value("${jwt.refreshable-duration}")
    protected long REFRESHABLE_DURATION;

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
        var user = userRepository
                .findByUserName(request.getUserName())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        boolean authenticated = passwordEncoder.matches(request.getPassWord(), user.getPassWord());

        if (!authenticated)
            throw new AppException(ErrorCode.UNAUTHENTICATED);

        var accessToken = generateAccessToken(user);
        var refreshToken = generateRefreshToken(user);

        LocalDateTime loginTime = LocalDateTime.now();
        user.setLastAccessTime(loginTime);
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .authenticated(true)
                .build();
    }

    private String generateAccessToken(User user) {

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUserName())
                .issuer("Application")
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("type", "access")
                .claim("scope", buildScope(user))
                .build();

        return signToken(jwtClaimsSet);
    }

    private String generateRefreshToken(User user) {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user.getUserName())
                .issuer("Application")
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now()
                                .plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS)
                                .toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("type", "refresh")
                .build();

        return signToken(claims);
    }

    private String signToken(JWTClaimsSet claimsSet) {

        try {

            SigningKey activeKey = keyService.getActiveKey();

            byte[] keyBytes = Base64.getDecoder()
                    .decode(activeKey.getPrivateKey());

            PrivateKey privateKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(
                            new PKCS8EncodedKeySpec(keyBytes));

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(activeKey.getKid())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);

            signedJWT.sign(
                    new RSASSASigner(
                            (RSAPrivateKey) privateKey));

            return signedJWT.serialize();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // private String signToken(JWTClaimsSet claimsSet) {

    // try {
    // SigningKey activeKey = keyService.getActiveKey();

    // JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS512)
    // .keyID(activeKey.getKid())
    // .build();

    // JWSObject jwsObject = new JWSObject(
    // header,
    // new Payload(claimsSet.toJSONObject()));

    // jwsObject.sign(
    // new MACSigner(activeKey.getSecret().getBytes()));

    // return jwsObject.serialize();

    // } catch (JOSEException e) {
    // throw new RuntimeException("Cannot sign token", e);
    // }
    // }

    public IntrospectResponse introspect(IntrospectRequest request) throws JOSEException, ParseException {
        boolean valid = true;

        try {
            String token = request.getToken();

            SignedJWT signedJWT = SignedJWT.parse(token);

            String type = signedJWT
                    .getJWTClaimsSet()
                    .getStringClaim("type");

            if ("access".equals(type)) {
                verifyAccessToken(token);
            } else {
                throw new AppException(ErrorCode.UNAUTHENTICATED);
            }

        } catch (Exception e) {
            valid = false;
        }

        return IntrospectResponse.builder()
                .valid(valid)
                .build();
    }

    private JWTClaimsSet verifyAccessToken(String token) {

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // String kid = signedJWT.getHeader().getKeyID();

            // SigningKey signingKey = keyService.getKeyByKid(kid);

            // boolean verified = signedJWT.verify(
            // new MACVerifier(signingKey.getSecret().getBytes()));

            String kid = signedJWT.getHeader().getKeyID();

            SigningKey signingKey = keyService.getKeyByKid(kid);

            byte[] keyBytes = Base64.getDecoder()
                    .decode(signingKey.getPublicKey());

            PublicKey publicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(
                            new X509EncodedKeySpec(keyBytes));

            boolean verified = signedJWT.verify(
                    new RSASSAVerifier(
                            (RSAPublicKey) publicKey));

            if (!verified)
                throw new AppException(ErrorCode.UNAUTHENTICATED);

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            if (claims.getExpirationTime().before(new Date()))
                throw new AppException(ErrorCode.UNAUTHENTICATED);

            if (!"access".equals(claims.getStringClaim("type")))
                throw new AppException(ErrorCode.UNAUTHENTICATED);

            if (invalidatedTokenRepository.existsById(claims.getJWTID()))
                throw new AppException(ErrorCode.UNAUTHENTICATED);

            return claims;

        } catch (Exception e) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
    }

    private JWTClaimsSet verifyRefreshToken(String token) {

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // String kid = signedJWT.getHeader().getKeyID();

            // SigningKey signingKey = keyService.getKeyByKid(kid);

            // boolean verified = signedJWT.verify(
            // new MACVerifier(signingKey.getSecret().getBytes()));

            String kid = signedJWT.getHeader().getKeyID();

            SigningKey signingKey = keyService.getKeyByKid(kid);

            byte[] keyBytes = Base64.getDecoder()
                    .decode(signingKey.getPublicKey());

            PublicKey publicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(
                            new X509EncodedKeySpec(keyBytes));

            boolean verified = signedJWT.verify(
                    new RSASSAVerifier(
                            (RSAPublicKey) publicKey));

            if (!verified)
                throw new AppException(ErrorCode.UNAUTHENTICATED);

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            if (claims.getExpirationTime().before(new Date()))
                throw new AppException(ErrorCode.UNAUTHENTICATED);

            if (!"refresh".equals(claims.getStringClaim("type")))
                throw new AppException(ErrorCode.UNAUTHENTICATED);

            return claims;

        } catch (Exception e) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
    }

    private String buildScope(User user) {
        StringJoiner stringJoiner = new StringJoiner(" ");

        if (!CollectionUtils.isEmpty(user.getRoles()))
            user.getRoles().forEach(role -> {
                stringJoiner.add("ROLE_" + role.getName());
                if (!CollectionUtils.isEmpty(role.getPermissions()))
                    role.getPermissions().forEach(permission -> stringJoiner.add(permission.getName()));
            });

        return stringJoiner.toString();
    }

    public AuthenticationResponse refreshToken(String refreshToken) throws ParseException, JOSEException {
        var claims = verifyRefreshToken(refreshToken);

        // blacklist refresh token cũ
        invalidatedTokenRepository.save(
                InvalidatedToken.builder()
                        .id(claims.getJWTID())
                        .expiryTime(claims.getExpirationTime())
                        .build());

        var user = userRepository.findByUserName(claims.getSubject())
                .orElseThrow(() -> new AppException(ErrorCode.UNAUTHENTICATED));

        return AuthenticationResponse.builder()
                .accessToken(generateAccessToken(user))
                .authenticated(true)
                .build();
    }

    public void logout(String refreshToken) throws ParseException, JOSEException {
        try {
            var claims = verifyRefreshToken(refreshToken);

            invalidatedTokenRepository.save(
                    InvalidatedToken.builder()
                            .id(claims.getJWTID())
                            .expiryTime(claims.getExpirationTime())
                            .build());
        } catch (AppException exception) {
            log.info("Token already expired");
        }
    }

}
