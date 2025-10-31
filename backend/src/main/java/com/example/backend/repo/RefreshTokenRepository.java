package com.example.backend.repo;

import com.example.backend.domain.RefreshToken;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    // Найти активный (не отозванный) refresh по хэшу
    Optional<RefreshToken> findByTokenHashAndRevokedFalse(String tokenHash);

    // Отозвать все refresh-токены пользователя (при логауте везде)
    @Modifying
    @Transactional
    @Query("update RefreshToken t set t.revoked = true where t.user.id = :userId and t.revoked = false")
    int revokeAllByUserId(@Param("userId") Long userId);

    // Удалить просроченные токены (фоновая чистка по крону/по расписанию)
    @Modifying
    @Transactional
    int deleteAllByExpiresAtBefore(Instant instant);
}