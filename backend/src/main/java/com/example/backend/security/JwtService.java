package com.example.backend.security;

import com.example.backend.domain.Role;
import com.example.backend.domain.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secretB64;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.access-ttl-min}")
    private long accessTtlMin;

    private SecretKey key;

    @PostConstruct
    void init() {
        // секрет читаем из Base64 (рекомендовано >= 32 байт)
        byte[] bytes;
        try {
            bytes = Decoders.BASE64.decode(secretB64);
        } catch (IllegalArgumentException e) {
            // на случай, если секрет передали не в base64 — fallback (но лучше всегда base64)
            bytes = secretB64.getBytes(StandardCharsets.UTF_8);
        }
        if (bytes.length < 32) {
            throw new IllegalStateException("app.jwt.secret must be >= 32 bytes");
        }
        this.key = Keys.hmacShaKeyFor(bytes);
    }

    /** Генерация короткоживущего access-токена. */
    public String generateAccess(User u) {
        Instant now = Instant.now();
        List<String> roleNames = u.getRoles().stream().map(Role::getName).toList();

        return Jwts.builder()
                .subject(u.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTtlMin, ChronoUnit.MINUTES)))
                .claim("email", u.getEmail())
                .claim("roles", roleNames)
                .signWith(key) // HS256 по типу ключа
                .compact();
    }

    /** Спарсить и провалидировать подпись/срок. Бросает JwtException при проблемах. */
    public Jws<Claims> parse(String token) throws JwtException {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }

    /** Достаём userId из токена (без доп. запросов к БД). */
    public Long extractUserId(String token) {
        var claims = parse(token).getPayload();
        return Long.valueOf(claims.getSubject());
    }

    public boolean isExpired(String token) {
        var exp = parse(token).getPayload().getExpiration();
        return exp != null && exp.toInstant().isBefore(Instant.now());
    }
}