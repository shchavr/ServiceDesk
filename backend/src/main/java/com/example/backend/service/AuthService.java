package com.example.backend.service;


import com.example.backend.common.CookieHelper;
import com.example.backend.domain.User;
import com.example.backend.repo.UserRepository;
import com.example.backend.security.JwtService;
import com.example.backend.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CookieHelper cookieHelper;

    @Value("${app.jwt.refresh-ttl-days}")
    private long refreshTtlDays;

    @Value("${app.jwt.access-ttl-min}")
    private long accessTtlMin;

    /** Логин по email+password: ставим refresh-куку, возвращаем access и TTL. */
    public TokenResponse login(String email, String password,
                               HttpServletRequest req, HttpServletResponse res) {

        User u = users.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!u.isEnabled() || u.isLocked()) {
            throw new RuntimeException("Account disabled/locked");
        }
        if (!passwordEncoder.matches(password, u.getPasswordHash())) {
            throw new RuntimeException("Bad credentials");
        }

        String ua = Optional.ofNullable(req.getHeader("User-Agent")).orElse("");
        String ip = Optional.ofNullable(req.getRemoteAddr()).orElse("");

        // выдать и сохранить refresh (в БД хранится только хэш), поставить HttpOnly cookie
        String rawRefresh = refreshTokenService.issueAndStore(u, ua, ip);
        cookieHelper.setRefreshCookie(res, rawRefresh, refreshTtlDays);

        // сгенерить короткий access
        String access = jwtService.generateAccess(u);
        long expiresIn = accessTtlMin * 60L;

        return new TokenResponse(access, expiresIn);
    }

    /** Обновить access по refresh-куке (ротация refresh внутри). */
    public TokenResponse refresh(HttpServletRequest req, HttpServletResponse res) {
        String raw = cookieHelper.readRefreshCookie(req)
                .orElseThrow(() -> new RuntimeException("No refresh cookie"));

        String ua = Optional.ofNullable(req.getHeader("User-Agent")).orElse("");
        String ip = Optional.ofNullable(req.getRemoteAddr()).orElse("");

        // проверяем и помечаем старый refresh как отозванный; возвращаем пользователя
        User user = refreshTokenService.consumeAndRotate(raw, ua, ip)
                .orElseThrow(() -> new RuntimeException("Invalid refresh"));

        // выдаём новый refresh и ставим новую HttpOnly cookie
        String newRaw = refreshTokenService.issueAndStore(user, ua, ip);
        cookieHelper.setRefreshCookie(res, newRaw, refreshTtlDays);

        // новый access
        String access = jwtService.generateAccess(user);
        long expiresIn = accessTtlMin * 60L;

        return new TokenResponse(access, expiresIn);
    }

    /** Логаут: отозвать все refresh пользователя и стереть куку. */
    public void logout(User currentUser, HttpServletResponse res) {
        if (currentUser != null) {
            refreshTokenService.revokeAll(currentUser);
        }
        cookieHelper.clearRefreshCookie(res);
    }
}