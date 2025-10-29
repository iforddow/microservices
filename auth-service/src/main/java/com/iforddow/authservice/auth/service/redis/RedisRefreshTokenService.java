package com.iforddow.authservice.auth.service.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class RedisRefreshTokenService {

    private final StringRedisTemplate stringRedisTemplate;

    @Value("${spring.data.redis.prefix}")
    private String servicePrefix;

    private String getTokenPrefix() {
        return  servicePrefix + "refreshToken:";
    }

    private String getUserTokensPrefix() {
        return  servicePrefix + "userTokens:";
    }

    /**
     * A method to store a refresh token in the redis
     * database.
     *
     * @author IFD
     * @since 2025-07-20
     * */
    public void storeToken(String hashedToken, UUID uuid, Instant expiresAt) {
        String tokenKey = getTokenPrefix() + hashedToken;
        String userTokensKey = getUserTokensPrefix() + uuid.toString();

        Duration ttl = Duration.between(Instant.now(), expiresAt);

        stringRedisTemplate.opsForValue().set(tokenKey, uuid.toString(), ttl);

        stringRedisTemplate.opsForSet().add(userTokensKey, hashedToken);
    }

    /*
     * A method to get the user id from
     * a refresh token.
     *
     * @author IFD
     * @since 2025-07-20
     * */
    public UUID getUserIdFromToken(String hashedToken) {
        String tokenKey = getTokenPrefix() + hashedToken;

        String value = stringRedisTemplate.opsForValue().get(tokenKey);

        return value != null ? UUID.fromString(value) : null;
    }

    /**
     * A method to revoke a token.
     *
     * @author IFD
     * @since 2025-07-20
     * */
    public void revokeToken(String hashedToken) {
        String tokenKey = getTokenPrefix() + hashedToken;

        // Get userId to remove token from user set
        String userIdStr = stringRedisTemplate.opsForValue().get(tokenKey);

        if (userIdStr != null) {
            String userTokensKey = getUserTokensPrefix() + userIdStr;

            // Remove token from user's token set
            stringRedisTemplate.opsForSet().remove(userTokensKey, hashedToken);
        }

        // Delete the token key itself
        stringRedisTemplate.delete(tokenKey);
    }

    /*
     * A method to revoke all tokens belonging to
     * a user.
     *
     * @author IFD
     * @since 2025-07-25
     * */
    public void revokeAllTokensForUser(UUID uuid) {
        String userTokensKey = getUserTokensPrefix() + uuid.toString();

        Set<String> userTokens = stringRedisTemplate.opsForSet().members(userTokensKey);

        if (userTokens != null && !userTokens.isEmpty()) {
            List<String> tokenKeys = userTokens.stream()
                    .map(token -> getTokenPrefix() + token)
                    .collect(Collectors.toList());
            stringRedisTemplate.delete(tokenKeys);
        }

        stringRedisTemplate.delete(userTokensKey);
    }

}
