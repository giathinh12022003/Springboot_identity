package com.microservices.identity_service.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.microservices.identity_service.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User,String> {
    boolean existsByUserName(String username);

    Optional<User> findByUserName(String username);
}
