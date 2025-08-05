package com.example.authapi.repository;

import com.example.authapi.entity.EmailVerificationToken;
import com.example.authapi.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {
    
    Optional<EmailVerificationToken> findByTokenHashAndUsedFalseAndExpiryTimeAfter(String tokenHash, LocalDateTime now);
    
    void deleteByUser(User user); // Optional cleanup
}
