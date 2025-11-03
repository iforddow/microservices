package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.request.LogoutRequest;
import com.iforddow.authservice.auth.utility.TokenHasher;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.utility.AuthServiceUtility;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
* A service class to log a user out of the application.
* Will revoke credentials.
*
* @author IFD
* @since 2025-10-27
* */
@RequiredArgsConstructor
@Service
public class LogoutService {

    private final TokenHasher tokenHasher;
    private final RedisRefreshTokenService redisRefreshTokenService;

    @Value("${jwt.cookie.name}")
    private String cookieName;

    /**
     * A method to handle user logout.
     *
     * @param logoutRequest Logout request settings
     * @param response HttpServletResponse variable
     * @author IFD
     * @since 2025-10-27
     */
    public void logout(LogoutRequest logoutRequest, HttpServletResponse response) {

        try {
            String refreshToken = logoutRequest.getRefreshToken();

            if (AuthServiceUtility.isNullOrEmpty(refreshToken)) {
                throw new BadRequestException("Refresh token is missing or empty");
            }

            String hashedRefreshToken = tokenHasher.hmacSha256(refreshToken);

            if (logoutRequest.isAllDevices()) {
                UUID userId = redisRefreshTokenService.getUserIdFromToken(hashedRefreshToken);

                if(userId == null) {
                    throw new BadRequestException("Invalid user refresh token");
                }
                redisRefreshTokenService.revokeAllTokensForUser(userId);
            } else {
                redisRefreshTokenService.revokeToken(hashedRefreshToken);
            }

        } finally {

            // Invalidate the refresh token by setting it to null
            Cookie cookie = new Cookie(cookieName, null);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            cookie.setSecure(true);

            response.addCookie(cookie);

        }

    }

}
