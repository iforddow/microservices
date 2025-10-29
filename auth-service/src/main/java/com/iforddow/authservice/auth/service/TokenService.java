package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.dto.LoginDTO;
import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.auth.request.RefreshTokenRequest;
import com.iforddow.authservice.auth.service.redis.RedisRefreshTokenService;
import com.iforddow.authservice.auth.utility.DeviceType;
import com.iforddow.authservice.auth.utility.TokenHasher;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.exception.ResourceNotFoundException;
import com.iforddow.authservice.common.security.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

/**
* A service class for the token service in the application.
* Will provide refresh token and token creation methods.
*
* @author IFD
* @since 2025-10-27
* */
@RequiredArgsConstructor
@Service
public class TokenService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final TokenHasher tokenHasher;
    private final RedisRefreshTokenService redisRefreshTokenService;

    @Value("${jwt.cookie.name}")
    private String cookieName;

    /**
     * A method to handle token refresh requests.
     *
     * @param refreshTokenRequest The refresh token request.
     * @return ResponseEntity containing the new access token if refresh is successful.
     * @author IFD
     * @since 2025-06-15
     */
    @Transactional
    public LoginDTO refreshToken(RefreshTokenRequest refreshTokenRequest, HttpServletResponse response) {

        if(!(refreshTokenRequest.getDeviceType() == DeviceType.WEB) && !refreshTokenRequest.getDeviceType().equals(DeviceType.MOBILE)) {
            throw new BadRequestException("Invalid device type");
        }

        String refreshToken = refreshTokenRequest.getRefreshToken();

        if(!jwtService.validateJwtToken(refreshToken)) {
            throw new BadRequestException("Invalid token");
        }

        String hashedRefreshToken = tokenHasher.hmacSha256(refreshToken);

        UUID userId = redisRefreshTokenService.getUserIdFromToken(hashedRefreshToken);

        if(userId == null) {
            throw new BadRequestException("Invalid token");
        }

        User user = userRepository.findById(userId).orElseThrow(
                () -> new ResourceNotFoundException("User not found")
        );

        redisRefreshTokenService.revokeToken(hashedRefreshToken);

        // Update the user's last active time
        user.setLastActive(new Date().toInstant());

        // Save the updated user back to the database
        userRepository.save(user);

        if(refreshTokenRequest.getDeviceType() == DeviceType.WEB) {
            createNewTokens(response, user, DeviceType.WEB);
            return null;
        } else {
            return createNewTokens(response, user, DeviceType.MOBILE);
        }

    }

    /**
     * A method to create tokens for the user
     * upon logging in and refresh.
     *
     * @author IFD
     * @since 2025-10-27
     */
    public LoginDTO createNewTokens(HttpServletResponse response, User user, DeviceType deviceType) {

        String newAccessToken;

        String newRefreshToken = jwtService.generateRefreshToken(user);
        String newHashedRefreshToken = tokenHasher.hmacSha256(newRefreshToken);

        redisRefreshTokenService.storeToken(newHashedRefreshToken, user.getId(), Instant.now().plusMillis(jwtService.jwtRefreshExpirationMs));

        if(deviceType == DeviceType.MOBILE) {
            newAccessToken = jwtService.generateJwtToken(user);
            return new LoginDTO(newAccessToken, newRefreshToken);
        }   else {
            Cookie refreshCookie = new Cookie(cookieName, newRefreshToken);

            refreshCookie.setHttpOnly(true);
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge(jwtService.jwtRefreshExpirationMs / 1000);
            refreshCookie.setSecure(true);

            response.addCookie(refreshCookie);

            return null;
        }

    }

}
