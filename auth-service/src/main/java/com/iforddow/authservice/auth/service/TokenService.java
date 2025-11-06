package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.utility.DeviceType;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.security.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.*;

/**
 * A service class for the token service in the application.
 * Will provide refresh token and token creation methods.
 * <p>
 * Note: The more this class is developed, the more it looks like
 * it should be merged with the JwtService. Will consider refactoring in the future.
 *
 * @author IFD
 * @since 2025-10-27
 * */
@RequiredArgsConstructor
@Service
public class TokenService {

    private final JwtService jwtService;
    private final RedisRefreshTokenService redisRefreshTokenService;

    @Value("${hmac.algo}")
    private String hmacAlgo;

    @Value("${hmac.secret}")
    private String hmacSecret;

    @Value("${jwt.cookie.name}")
    private String cookieName;

    /**
     * A method to create tokens for the user
     * upon logging in and refresh.
     *
     * @author IFD
     * @since 2025-10-27
     */
    public String createNewTokens(User user, DeviceType deviceType, HttpServletResponse response) {

        // Create a new refresh token
        String newRefreshToken = jwtService.generateRefreshToken(user);

        // Hash the new refresh token
        String newHashedRefreshToken = hmacSha256(newRefreshToken);

        // Store the new refresh token (hashed) in Redis
        redisRefreshTokenService.storeToken(newHashedRefreshToken, user.getId(), jwtService.getExpirationFromToken(newRefreshToken));

        // If mobile device, return the refresh token in response body
        if(deviceType == DeviceType.MOBILE) {
            return newRefreshToken;
        }   else {

            // Calculate max age for cookie
            long secondsLeft = jwtService.getExpirationFromToken(newRefreshToken).getEpochSecond()
                    - Instant.now().getEpochSecond();
            int maxAge = (int) Math.min(Integer.MAX_VALUE, Math.max(0L, secondsLeft));

            // For web, set the refresh token in an HttpOnly cookie
            Cookie refreshCookie = new Cookie(cookieName, newRefreshToken);

            refreshCookie.setHttpOnly(true);
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge(maxAge);
            refreshCookie.setAttribute("SameSite", "Secure");
            refreshCookie.setSecure(true);

            response.addCookie(refreshCookie);

            return null;
        }

    }

    /**
     * A method to hash a String using
     * SHA-256 algorithm.
     *
     * @author IFD
     * @since 2025-10-27
     * */
    public String hmacSha256(String str) {

        try {
            SecretKeySpec keySpec = new SecretKeySpec(hmacSecret.getBytes(), hmacAlgo);
            Mac mac = Mac.getInstance(hmacAlgo);
            mac.init(keySpec);

            byte[] rawHmac = mac.doFinal(str.getBytes());

            return Base64.getEncoder().encodeToString(rawHmac);

        } catch (Exception e) {
            throw new RuntimeException(e);
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

        if (tokenFromHeader != null) {
            return tokenFromHeader;
        }

        throw new BadRequestException("No token provided.");

    }

}
