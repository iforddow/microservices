package com.iforddow.authservice.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/*
* A service class for refresh token storage in Redis.
*
* @author IFD
* @since 2025-10-29
* */
@RequiredArgsConstructor
@Service
public class RedisRefreshTokenService {

    private final StringRedisTemplate stringRedisTemplate;

    @Value("${spring.data.redis.prefix}")
    private String servicePrefix;

    /**
    * A method to get the redis token prefix.
    *
    * @author IFD
    * @since 2025-10-29
    * */
    private String getTokenPrefix() {
        return  servicePrefix + "refreshToken:";
    }

    /**
    * A method to get the redis user token prefix.
    *
    * @author IFD
    * @since 2025-10-29
    * */
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

        // Use sorted set with current timestamp as score
        stringRedisTemplate.opsForZSet().add(userTokensKey, hashedToken, System.currentTimeMillis());
        stringRedisTemplate.expire(userTokensKey, ttl);
    }

    /**
     * A method to clean up expired tokens from user's token set.
     *
     * @author IFD
     * @since 2025-10-29
     * */
    public void cleanupExpiredTokensForUser(UUID uuid) {
        String userTokensKey = getUserTokensPrefix() + uuid.toString();
        Set<String> userTokens = stringRedisTemplate.opsForZSet().range(userTokensKey, 0, -1);

        if (userTokens != null && !userTokens.isEmpty()) {
            for (String hashedToken : userTokens) {
                String tokenKey = getTokenPrefix() + hashedToken;
                // If token doesn't exist (expired), remove from user set
                if (!stringRedisTemplate.hasKey(tokenKey)) {
                    stringRedisTemplate.opsForZSet().remove(userTokensKey, hashedToken);
                }
            }
        }
    }

    /**
     * A method to get valid (non-expired) tokens for a user.
     *
     * @author IFD
     * @since 2025-10-29
     * */
    public Set<String> getValidTokensForUser(UUID uuid) {
        if (uuid == null) {
            throw new IllegalArgumentException("UUID cannot be null");
        }

        cleanupExpiredTokensForUser(uuid);
        String userTokensKey = getUserTokensPrefix() + uuid;

        // Safely handle potential null from count()
        Long count = stringRedisTemplate.opsForZSet().zCard(userTokensKey);
        if (count != null && count > 1000) {
            throw new IllegalStateException("User has too many active tokens: " + count);
        }

        Set<String> tokens = stringRedisTemplate.opsForZSet().range(userTokensKey, 0, -1);
        return tokens != null ? tokens : Collections.emptySet();
    }

    /**
     * A method to revoke the oldest tokens for a user atomically.
     *
     * @author IFD
     * @since 2025-10-29
     */
    public void revokeOldestTokens(UUID userId, int tokensToRevoke) {
        if (userId == null) {
            throw new IllegalArgumentException("UserId cannot be null");
        }
        if (tokensToRevoke <= 0) {
            return;
        }

        String userTokensKey = getUserTokensPrefix() + userId;
        String tokenPrefix = getTokenPrefix();

        // Lua script for atomic operation
        String luaScript = """
        local userTokensKey = KEYS[1]
        local tokenPrefix = ARGV[1]
        local tokensToRevoke = tonumber(ARGV[2])
        
        -- Get oldest tokens
        local oldestTokens = redis.call('ZRANGE', userTokensKey, 0, tokensToRevoke - 1)
        
        -- Revoke each token
        for i, token in ipairs(oldestTokens) do
            local tokenKey = tokenPrefix .. token
            redis.call('DEL', tokenKey)
            redis.call('ZREM', userTokensKey, token)
        end
        
        return #oldestTokens
        """;

        try {
            stringRedisTemplate.execute(
                    RedisScript.of(luaScript, Long.class),
                    Collections.singletonList(userTokensKey),
                    tokenPrefix,
                    String.valueOf(tokensToRevoke)
            );
        } catch (Exception e) {
            System.err.println("Failed to revoke oldest tokens for user " + userId + ": " + e.getMessage());
        }
    }

    /**
     * A method to get the user id from
     * a refresh token.
     *
     * @author IFD
     * @since 2025-10-30
     * */
    public UUID getUserIdFromToken(String hashedToken) {
        String tokenKey = getTokenPrefix() + hashedToken;
        String value = stringRedisTemplate.opsForValue().get(tokenKey);

        if (value != null) {
            try {
                return UUID.fromString(value);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * A method to revoke a token.
     *
     * @author IFD
     * @since 2025-07-20
     */
    public void revokeToken(String hashedToken) {
        String tokenKey = getTokenPrefix() + hashedToken;

        // Get userId to remove token from user set
        String userIdStr = stringRedisTemplate.opsForValue().get(tokenKey);

        if (userIdStr != null) {
            String userTokensKey = getUserTokensPrefix() + userIdStr;

            // Remove token from user's sorted set
            stringRedisTemplate.opsForZSet().remove(userTokensKey, hashedToken);
        }

        // Delete the token key itself
        stringRedisTemplate.delete(tokenKey);
    }

    /**
     * A method to revoke all tokens belonging to a user.
     *
     * @author IFD
     * @since 2025-07-25
     */
    public void revokeAllTokensForUser(UUID uuid) {
        String userTokensKey = getUserTokensPrefix() + uuid.toString();

        Set<String> userTokens = stringRedisTemplate.opsForZSet().range(userTokensKey, 0, -1);

        if (userTokens != null && !userTokens.isEmpty()) {
            List<String> tokenKeys = userTokens.stream()
                    .map(token -> getTokenPrefix() + token)
                    .collect(Collectors.toList());
            stringRedisTemplate.delete(tokenKeys);
        }

        stringRedisTemplate.delete(userTokensKey);
    }

}
