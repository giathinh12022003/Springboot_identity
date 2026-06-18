package com.microservices.identity_service.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import com.microservices.identity_service.entity.SigningKey;
import com.microservices.identity_service.enums.KeyStatus;

public interface SigningKeyRepository extends JpaRepository<SigningKey, String> {

    Optional<SigningKey> findFirstByStatusOrderByCreatedAtDesc(KeyStatus status);

}
