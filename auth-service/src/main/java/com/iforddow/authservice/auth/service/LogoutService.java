package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.request.LogoutRequest;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.utility.AuthServiceUtility;
import com.iforddow.authservice.common.utility.HashUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
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

    private final RedisSessionTokenService redisSessionTokenService;
    private final HashUtil hashUtil;

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
    public void logout(LogoutRequest logoutRequest, String existingToken, HttpServletResponse response) {

        // Use try-finally to ensure cookie is removed
        try {

            if (AuthServiceUtility.isNullOrEmpty(existingToken)) {
                throw new BadRequestException("No authentication session found.");
            }

            String hashedSessionToken = hashUtil.hmacSha256(existingToken);

            // If all devices is true, revoke all tokens for the user (logout from all devices)
            if (logoutRequest.isAllDevices()) {

                // Get user ID from the session token
                UUID userId = redisSessionTokenService.getUserIdFromToken(hashedSessionToken);

                // If no user ID found, throw an exception
                if(userId == null) {
                    throw new BadRequestException("Could not find user for the provided token.");
                }

                // Revoke all session tokens for the user
                redisSessionTokenService.revokeAllTokensForUser(userId);
            } else {

                // Revoke only the current session token
                redisSessionTokenService.revokeToken(hashedSessionToken);
            }

        } finally {

            // Invalidate the session token by setting it to null
            // This will remove the cookie from the client side
            // no matter what happens in the try block.
            //
            // If the user is on mobile this cookie won't exist,
            // but this won't cause any issues.

            Cookie cookie = new Cookie(cookieName, null);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            cookie.setSecure(true);

            response.addCookie(cookie);

        }

    }

}
