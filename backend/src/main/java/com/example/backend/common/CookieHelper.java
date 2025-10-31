package com.example.backend.common;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import jakarta.servlet.http.Cookie;

@Component
public class CookieHelper {

    // dev: false (на localhost без https)
    // prod: true  (обязательно на https)
    @Value("${app.refresh.cookie.secure:false}")
    private boolean secure;

    // Lax для same-site на одном домене; при кросс-домене в проде ставь None
    @Value("${app.refresh.cookie.samesite:Lax}")
    private String sameSite;

    // путь, на который будет отправляться кука
    @Value("${app.refresh.cookie.path:/auth/refresh}")
    private String path;

    // имя куки
    @Value("${app.refresh.cookie.name:refresh}")
    private String cookieName;

    /** Установить HttpOnly refresh-куку. */
    public void setRefreshCookie(HttpServletResponse res, String rawToken, long ttlDays) {
        ResponseCookie cookie = ResponseCookie.from(cookieName, rawToken)
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)       // "Lax" | "None" (для cross-site) | "Strict"
                .path(path)
                .maxAge(Duration.ofDays(ttlDays))
                .build();
        res.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /** Стереть refresh-куку. */
    public void clearRefreshCookie(HttpServletResponse res) {
        ResponseCookie cookie = ResponseCookie.from(cookieName, "")
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .path(path)
                .maxAge(Duration.ZERO)
                .build();
        res.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /** Прочитать refresh-куку из запроса. */
    public Optional<String> readRefreshCookie(HttpServletRequest req) {
        if (req.getCookies() == null) return Optional.empty();
        return Arrays.stream(req.getCookies())
                .filter(c -> cookieName.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
}