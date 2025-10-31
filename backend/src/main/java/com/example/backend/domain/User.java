package com.example.backend.domain;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users", indexes = {
        @Index(name = "ux_users_email", columnList = "email", unique = true),
        @Index(name = "ix_users_phone", columnList = "phone")
})
@Getter @Setter @NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Логин
    @Email @NotBlank
    @Column(nullable = false, unique = true, length = 320)
    private String email;

    @NotBlank
    @Column(nullable = false, length = 100)
    private String passwordHash;

    // Профиль
    @Column(length = 100)
    private String firstName;

    @Column(length = 100)
    private String lastName;

    @Column(length = 255)
    private String workplace;

    @Column(length = 100)
    private String position;


    @Pattern(regexp = "^[+\\d][\\d\\s()\\-]{6,30}$",
            message = "Некорректный номер телефона")
    @Column(length = 32)
    private String phone;

    // Статус
    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private boolean locked = false;

    // Роли
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id", foreignKey = @ForeignKey(name = "fk_ur_user")),
            inverseJoinColumns = @JoinColumn(name = "role_id", foreignKey = @ForeignKey(name = "fk_ur_role"))
    )
    private Set<Role> roles = new HashSet<>();
}
