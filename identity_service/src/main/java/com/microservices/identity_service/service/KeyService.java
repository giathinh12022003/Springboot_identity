package com.microservices.identity_service.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.microservices.identity_service.entity.SigningKey;
import com.microservices.identity_service.enums.KeyStatus;
import com.microservices.identity_service.repository.SigningKeyRepository;

import jakarta.annotation.PostConstruct;

import java.util.Base64;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class KeyService {

    private final SigningKeyRepository keyRepository;
    private final RedisTemplate<String, String> redisTemplate;

    private static final String PRIVATE_KEY_PREFIX = "private_key:";
    private static final String PUBLIC_KEY_PREFIX = "public_key:";

    @PostConstruct
    public void initKey() {
        if (keyRepository.count() == 0) {
            log.info("No signing key found, generating initial key...");
            rotateKey();
        }
    }

    // ================= GET ACTIVE KEY =================
    public SigningKey getActiveKey() {

        // 1. check Redis
        String kid = redisTemplate.opsForValue().get("active_kid");

        if (kid != null) {
            String privateKey = redisTemplate.opsForValue().get(PRIVATE_KEY_PREFIX + kid);
            String publicKey = redisTemplate.opsForValue().get(PUBLIC_KEY_PREFIX + kid);
            if (privateKey != null && publicKey != null) {
                return SigningKey.builder()
                        .kid(kid)
                        .privateKey(privateKey)
                        .publicKey(publicKey)
                        .status(KeyStatus.ACTIVE)
                        .build();
            }
        }

        // 2. fallback DB
        SigningKey key = keyRepository
                .findFirstByStatusOrderByCreatedAtDesc(KeyStatus.ACTIVE)
                .orElseThrow(() -> new RuntimeException("No active key"));

        // cache lại
        cacheKey(key);

        return key;
    }

    // ================= GET KEY BY KID =================
    public SigningKey getKeyByKid(String kid) {

        String privateKey = redisTemplate.opsForValue().get(PRIVATE_KEY_PREFIX + kid);
        String publicKey = redisTemplate.opsForValue().get(PUBLIC_KEY_PREFIX + kid);

        if (privateKey != null && publicKey != null) {
            return SigningKey.builder()
                    .kid(kid)
                    .privateKey(privateKey)
                    .publicKey(publicKey)
                    .build();
        }

        SigningKey key = keyRepository.findById(kid)
                .orElseThrow(() -> new RuntimeException("Key not found"));

        cacheKey(key);

        return key;
    }

    // ================= ROTATE KEY =================
    // @Scheduled(cron = "0 0 0 * * ?") // mỗi ngày
    @Scheduled(fixedRate = 30000)
    public void rotateKey() {

        log.info("Start rotating key...");

        SigningKey newKey = generateRsaKey();

        keyRepository.findFirstByStatusOrderByCreatedAtDesc(KeyStatus.ACTIVE)
                .ifPresent(oldKey -> {
                    oldKey.setStatus(KeyStatus.RETIRED);
                    keyRepository.save(oldKey);
                });

        keyRepository.save(newKey);

        cacheKey(newKey);

        log.info("Key rotated. New kid={}", newKey.getKid());
    }

    // ================= CLEAN OLD KEYS =================
    // @Scheduled(cron = "0 0 3 * * ?")
    @Scheduled(fixedRate = 50000)
    public void cleanOldKeys() {

        List<SigningKey> keys = keyRepository.findAll();

        keys.stream()
                .filter(k -> k.getExpiresAt().isBefore(LocalDateTime.now()))
                .forEach(k -> {

                    keyRepository.delete(k);

                    redisTemplate.delete(List.of(
                            PRIVATE_KEY_PREFIX + k.getKid(),
                            PUBLIC_KEY_PREFIX + k.getKid()));
                });
    }

    // ================= CACHE =================
    private void cacheKey(SigningKey key) {
        redisTemplate.opsForValue().set(PRIVATE_KEY_PREFIX + key.getKid(), key.getPrivateKey());
        redisTemplate.opsForValue().set(PUBLIC_KEY_PREFIX + key.getKid(), key.getPublicKey());
        if (key.getStatus() == KeyStatus.ACTIVE) {
            redisTemplate.opsForValue().set("active_kid", key.getKid());
        }
    }

    // ================= GENERATE KEY =================
    // private String generateSecureKey() {

    // SecureRandom random = new SecureRandom();
    // byte[] bytes = new byte[64];
    // random.nextBytes(bytes);

    // return Base64.getEncoder().encodeToString(bytes);
    // }

    private SigningKey generateRsaKey() {

        try {
            String kid = UUID.randomUUID().toString();

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

            generator.initialize(2048);

            KeyPair keyPair = generator.generateKeyPair();

            String privateKey = Base64.getEncoder()
                    .encodeToString(keyPair.getPrivate().getEncoded());

            String publicKey = Base64.getEncoder()
                    .encodeToString(keyPair.getPublic().getEncoded());

            return SigningKey.builder()
                    .kid(kid)
                    .privateKey(privateKey)
                    .publicKey(publicKey)
                    .status(KeyStatus.ACTIVE)
                    .createdAt(LocalDateTime.now())
                    .expiresAt(LocalDateTime.now().plusMinutes(2))
                    .build();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Cannot generate RSA key", e);
        }
    }
}