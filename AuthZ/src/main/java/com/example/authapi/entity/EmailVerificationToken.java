package com.example.authapi.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerificationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String tokenHash;
    private LocalDateTime expiryTime;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;

    private boolean used = false;
}
