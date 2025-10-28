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
    private static String servicePrefix;

    private static final String TOKEN_PREFIX = servicePrefix +  "refreshToken:";
    private static final String USER_TOKENS_PREFIX = servicePrefix + "userTokens:";


    /**
     * A method to store a refresh token in the redis
     * database.
     *
     * @author IFD
     * @since 2025-07-20
     * */
    public void storeToken(String hashedToken, UUID uuid, Instant expiresAt) {
        String tokenKey = TOKEN_PREFIX + hashedToken;
        String userTokensKey = USER_TOKENS_PREFIX + uuid.toString();

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
        String tokenKey = TOKEN_PREFIX + hashedToken;

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
        String tokenKey = TOKEN_PREFIX + hashedToken;

        // Get userId to remove token from user set
        String userIdStr = stringRedisTemplate.opsForValue().get(tokenKey);

        if (userIdStr != null) {
            String userTokensKey = USER_TOKENS_PREFIX + userIdStr;

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
        String userTokensKey = USER_TOKENS_PREFIX + uuid.toString();

        Set<String> userTokens = stringRedisTemplate.opsForSet().members(userTokensKey);

        if (userTokens != null && !userTokens.isEmpty()) {
            List<String> tokenKeys = userTokens.stream()
                    .map(token -> TOKEN_PREFIX + token)
                    .collect(Collectors.toList());
            stringRedisTemplate.delete(tokenKeys);
        }

        stringRedisTemplate.delete(userTokensKey);
    }

}
