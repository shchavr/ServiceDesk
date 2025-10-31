package com.example.backend.controller;

import com.example.backend.domain.User;
import com.example.backend.repo.RoleRepository;
import com.example.backend.repo.UserRepository;
import com.example.backend.service.AuthService;
import com.example.backend.dto.LoginRequest;
import com.example.backend.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository users;
    private final RoleRepository roles;
    private final PasswordEncoder passwordEncoder;

    /** Простая регистрация по email+password. */
    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody @Valid LoginRequest req) {
        if (users.existsByEmail(req.email())) return ResponseEntity.status(409).build();

        var u = new User();
        u.setEmail(req.email());
        u.setPasswordHash(passwordEncoder.encode(req.password()));
        u.setEnabled(true);
        u.setLocked(false);
        // если в БД есть роль "Пользователь" — назначим
        roles.findByName("Пользователь").ifPresent(u.getRoles()::add);

        users.save(u);
        return ResponseEntity.ok().build();
    }

    /** Логин: ставим HttpOnly refresh-куку и возвращаем access. */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody @Valid LoginRequest req,
                                               HttpServletRequest httpReq,
                                               HttpServletResponse httpRes) {
        return ResponseEntity.ok(authService.login(req.email(), req.password(), httpReq, httpRes));
    }

    /** Рефреш access по refresh-куке (ротация refresh внутри). */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(HttpServletRequest httpReq,
                                                 HttpServletResponse httpRes) {
        return ResponseEntity.ok(authService.refresh(httpReq, httpRes));
    }

    /** Логаут: отозвать refresh(и) и стереть куку. */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(Authentication auth, HttpServletResponse httpRes) {
        User current = (auth != null && auth.getPrincipal() instanceof User u) ? u : null;
        authService.logout(current, httpRes);
        return ResponseEntity.ok().build();
    }
}
