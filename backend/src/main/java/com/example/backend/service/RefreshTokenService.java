package com.example.backend.service;

import com.example.backend.domain.RefreshToken;
import com.example.backend.domain.User;
import com.example.backend.repo.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository tokens;

    @Value("${app.jwt.refresh-ttl-days}")
    private long refreshTtlDays;

    /** Выдать новый refresh-токен (сырой вернуть клиенту в HttpOnly cookie), в БД хранится только hash. */
    public String issueAndStore(User user, String userAgent, String ip) {
        String raw = UUID.randomUUID() + ":" + user.getId(); // случайный материал + привязка к юзеру
        String hash = hash(raw);

        var rec = new RefreshToken();
        rec.setUser(user);
        rec.setTokenHash(hash);
        rec.setExpiresAt(Instant.now().plus(refreshTtlDays, ChronoUnit.DAYS));
        rec.setUserAgent(userAgent);
        rec.setIp(ip);
        tokens.save(rec);

        return raw;
    }

    /** Проверить raw refresh, отозвать его (ротация) и вернуть пользователя, если всё ок. */
    public Optional<User> consumeAndRotate(String raw, String userAgent, String ip) {
        var recOpt = tokens.findByTokenHashAndRevokedFalse(hash(raw));
        if (recOpt.isEmpty()) return Optional.empty();

        var rec = recOpt.get();
        if (rec.getExpiresAt().isBefore(Instant.now())) return Optional.empty();

        // отзыв текущего
        rec.setRevoked(true);
        rec.setRotatedAt(Instant.now());
        tokens.save(rec);

        // новый токен для этого же пользователя (можно создавать тут или в вызывающем сервисе)
        return Optional.of(rec.getUser());
    }

    /** Отозвать все refresh-токены пользователя (например, logout from all devices). */
    public void revokeAll(User user) {
        tokens.revokeAllByUserId(user.getId());
    }

    /** Утилита: SHA-256 → Base64 (храним хэш, а не сырой токен). */
    private String hash(String raw) {
        try {
            var md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}