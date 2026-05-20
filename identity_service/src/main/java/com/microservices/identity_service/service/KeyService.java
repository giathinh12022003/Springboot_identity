package com.microservices.identity_service.service;

import java.security.SecureRandom;
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

    private static final String KEY_PREFIX = "signing_key:";

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
            String secret = redisTemplate.opsForValue().get(KEY_PREFIX + kid);
            if (secret != null) {
                return SigningKey.builder()
                        .kid(kid)
                        .secret(secret)
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

        String secret = redisTemplate.opsForValue().get(KEY_PREFIX + kid);

        if (secret != null) {
            return SigningKey.builder()
                    .kid(kid)
                    .secret(secret)
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

        // 1. tạo key mới
        String kid = UUID.randomUUID().toString();
        String secret = generateSecureKey();

        SigningKey newKey = SigningKey.builder()
                .kid(kid)
                .secret(secret)
                .status(KeyStatus.ACTIVE)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(2))
                // .expiresAt(LocalDateTime.now().plusDays(7))
                .build();

        // 2. set key cũ → RETIRED
        keyRepository.findFirstByStatusOrderByCreatedAtDesc(KeyStatus.ACTIVE)
                .ifPresent(oldKey -> {
                    oldKey.setStatus(KeyStatus.RETIRED);
                    keyRepository.save(oldKey);
                });

        // 3. save key mới
        keyRepository.save(newKey);

        // 4. cache
        cacheKey(newKey);

        log.info("Key rotated. New kid={}", kid);
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
                    redisTemplate.delete(KEY_PREFIX + k.getKid());
                });
    }

    // ================= CACHE =================
    private void cacheKey(SigningKey key) {
        redisTemplate.opsForValue().set(KEY_PREFIX + key.getKid(), key.getSecret());
        if (key.getStatus() == KeyStatus.ACTIVE) {
            redisTemplate.opsForValue().set("active_kid", key.getKid());
        }
    }

    // ================= GENERATE KEY =================
    private String generateSecureKey() {

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);

        return Base64.getEncoder().encodeToString(bytes);
    }
}