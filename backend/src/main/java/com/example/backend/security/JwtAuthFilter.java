package com.example.backend.security;


import com.example.backend.domain.User;
import com.example.backend.repo.UserRepository;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        String p = req.getRequestURI();
        return p.startsWith("/auth/")
                || p.startsWith("/swagger-ui/")
                || p.startsWith("/v3/api-docs")   // и JSON, и /v3/api-docs.yaml
                || p.equals("/actuator/health")
                || "OPTIONS".equalsIgnoreCase(req.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        // уже аутентифицирован — пропускаем
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(req, res);
            return;
        }

        String header = req.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                Long userId = jwtService.extractUserId(token); // внутри parse+verify

                User user = userRepository.findById(userId).orElse(null);
                if (user != null && user.isEnabled() && !user.isLocked()) {
                    var authorities = user.getRoles().stream()
                            .map(r -> new SimpleGrantedAuthority(
                                    r.getName().startsWith("ROLE_") ? r.getName() : "ROLE_" + r.getName()))
                            .toList();

                    var auth = new UsernamePasswordAuthenticationToken(
                            /* principal лучше облегчить, но оставлю как у тебя: */ user, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (JwtException | IllegalArgumentException e) {
                // битый токен — не аутентифицируем, но swagger мы сюда не пускаем через shouldNotFilter
                SecurityContextHolder.clearContext();
            }
        }

        chain.doFilter(req, res);
    }
}