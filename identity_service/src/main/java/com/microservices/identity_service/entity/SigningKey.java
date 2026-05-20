package com.microservices.identity_service.entity;

import java.time.LocalDateTime;

import com.microservices.identity_service.enums.KeyStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "signing_keys")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SigningKey {

    @Id
    private String kid;

    @Column(nullable = false)
    private String secret;

    @Enumerated(EnumType.STRING)
    private KeyStatus status; // ACTIVE, RETIRED

    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
}
