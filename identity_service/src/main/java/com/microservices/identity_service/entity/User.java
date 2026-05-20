package com.microservices.identity_service.entity;

import java.time.LocalDateTime;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;

import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Entity
@Data
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    String id;

    @Column(name = "user_name", nullable = false, columnDefinition = "TEXT", unique = true)
    String userName;

    @Column(name = "password", nullable = false, columnDefinition = "TEXT")
    String passWord;

    @Column(name = "name",  nullable = false, columnDefinition = "TEXT")
    String name;

    @Column(name = "phone_number", nullable = false, columnDefinition = "TEXT")
    String phoneNumber;

    @Column(name = "email", columnDefinition = "TEXT")
    String email;

    @Column(name = "status", nullable = false, columnDefinition = "TEXT")
    String status;

    @Column(name = "created_at", nullable = false, updatable = false)
    LocalDateTime createdAt;

    @Column(name = "last_access_time")
    LocalDateTime lastAccessTime;

    @Column(name = "last_updated")
    LocalDateTime lastUpdated;

    @ManyToMany
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    Set<Role> roles;


    @PrePersist
    private void prePersist() {
        this.createdAt = LocalDateTime.now();
        this.status = "ACTIVE";
    }
}
