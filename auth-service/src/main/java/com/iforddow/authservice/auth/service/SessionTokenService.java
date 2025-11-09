package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.utility.DeviceType;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.security.JwtService;
import com.iforddow.authservice.common.utility.HashUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.*;

/**
 * A service class for the token service in the application.
 * Will provide session token and token creation methods.
 * <p>
 * Note: The more this class is developed, the more it looks like
 * it should be merged with the JwtService. Will consider refactoring in the future.
 *
 * @author IFD
 * @since 2025-10-27
 * */
@RequiredArgsConstructor
@Service
public class SessionTokenService {

    private final JwtService jwtService;
    private final RedisSessionTokenService redisSessionTokenService;
    private final HashUtil hashUtil;

    @Value("${jwt.cookie.name}")
    private String cookieName;

    /**
     * A method to create tokens for the user
     * upon logging in and session refresh.
     *
     * @author IFD
     * @since 2025-10-27
     */
    public String createNewTokens(User user, DeviceType deviceType, HttpServletResponse response) {

        // Create a new session token
        String newSessionToken = jwtService.generateSessionToken(user);

        // Hash the new session token
        String newHashedSessionToken = hashUtil.hmacSha256(newSessionToken);

        // Store the new session token (hashed) in Redis
        redisSessionTokenService.storeToken(newHashedSessionToken, user.getId(), jwtService.getExpirationFromToken(newSessionToken));

        // If mobile device, return the session token in response body
        if(deviceType == DeviceType.MOBILE) {
            return newSessionToken;
        }   else {

            // Calculate max age for cookie
            long secondsLeft = jwtService.getExpirationFromToken(newSessionToken).getEpochSecond()
                    - Instant.now().getEpochSecond();
            int maxAge = (int) Math.min(Integer.MAX_VALUE, Math.max(0L, secondsLeft));

            // For web, set the session token in an HttpOnly cookie
            Cookie sessionCookie = new Cookie(cookieName, newSessionToken);

            sessionCookie.setHttpOnly(true);
            sessionCookie.setPath("/");
            sessionCookie.setMaxAge(maxAge);
            sessionCookie.setAttribute("SameSite", "Secure");
            sessionCookie.setSecure(true);

            response.addCookie(sessionCookie);

            return null;
        }

    }

    /**
     * A method to normalize a token by removing the "Bearer " prefix if present.
     *
     * @param header The header or token string to normalize.
     * @return The normalized token string.
     *
     * @author IFD
     * @since 2025-11-04
     * */
    public String extractTokenFromHeader(String header) {
        if (header == null) return null;
        String value = header.trim();
        if (value.toLowerCase().startsWith("bearer ")) {
            return value.substring(7).trim();
        }
        return value;
    }

    /**
    * A method to ensure that only one token is provided
    * either via cookie or Authorization header. If both or none
    * are provided, an exception is thrown. This helps as
    * mobile apps will send tokens in headers while web apps
    * will use cookies.
    *
    * @param cookie The token from the cookie.
    * @param authHeader The Authorization header value.
    * @return The single token provided.
    *
    * @author IFD
    * @since 2025-11-05
    * */
    public String ensureOneToken(String cookie, String authHeader) {

        String tokenFromHeader = extractTokenFromHeader(authHeader);

        if (cookie != null && tokenFromHeader != null) {
            throw new BadRequestException("Multiple tokens provided. Please provide only one token.");
        }

        if (cookie != null) {
            return cookie;
        }

        return tokenFromHeader;

    }

}
