package com.iforddow.authservice.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "\"user\"")
public class User implements UserDetails {
    @Id
    @GeneratedValue
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "email", nullable = false, length = 150)
    private String email;

    @Column(name = "password", nullable = false)
    private String password;

    @Builder.Default
    @ColumnDefault("true")
    @Column(name = "enabled", nullable = false)
    private Boolean enabled = true;

    @Builder.Default
    @ColumnDefault("false")
    @Column(name = "expired", nullable = false)
    private Boolean expired = false;

    @Builder.Default
    @ColumnDefault("false")
    @Column(name = "locked", nullable = false)
    private Boolean locked = false;

    @Builder.Default
    @ColumnDefault("false")
    @Column(name = "credentials_expired", nullable = false)
    private Boolean credentialsExpired = false;

    @Builder.Default
    @ColumnDefault("false")
    @Column(name = "user_verified", nullable = false)
    private Boolean userVerified = false;

    @Builder.Default
    @ColumnDefault("now()")
    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Builder.Default
    @ColumnDefault("now()")
    @Column(name = "last_active", nullable = false)
    private Instant lastActive = Instant.now();

    @Transient
    private List<String> authorities = new ArrayList<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.stream().map(SimpleGrantedAuthority::new).toList();
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !expired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}