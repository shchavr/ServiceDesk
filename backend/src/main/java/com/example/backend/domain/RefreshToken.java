package com.example.backend.domain;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "ix_rt_user", columnList = "user_id"),
        @Index(name = "ux_rt_token_hash", columnList = "tokenHash", unique = true),
        @Index(name = "ix_rt_expires", columnList = "expiresAt")
})
@Getter @Setter @NoArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_rt_user"))
    private User user;

    @Column(nullable = false, length = 88)
    private String tokenHash;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked = false;

    private Instant rotatedAt;

    @Column(length = 255)
    private String userAgent;

    @Column(length = 45) // IPv6 влезет
    private String ip;
}