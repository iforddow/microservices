package com.iforddow.authservice.auth.service;

import com.iforddow.authservice.auth.dto.LoginDTO;
import com.iforddow.authservice.auth.entity.User;
import com.iforddow.authservice.auth.repository.UserRepository;
import com.iforddow.authservice.auth.request.LoginRequest;
import com.iforddow.authservice.auth.service.redis.RedisRefreshTokenService;
import com.iforddow.authservice.auth.utility.DeviceType;
import com.iforddow.authservice.auth.utility.TokenHasher;
import com.iforddow.authservice.common.exception.BadRequestException;
import com.iforddow.authservice.common.exception.InvalidCredentialsException;
import com.iforddow.authservice.common.exception.ResourceNotFoundException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * A service class for user login methods.
 *
 * @author IFD
 * @since 2025-10-27
 * */
@RequiredArgsConstructor
@Service
public class LoginService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final RedisRefreshTokenService redisRefreshTokenService;
    private final TokenHasher tokenHasher;

    /**
     * A method to handle user login.
     *
     * @param loginRequest The request object containing user login details.
     * @author IFD
     * @since 2025-10-27
     */
    @Transactional
    public LoginDTO authenticate(LoginRequest loginRequest, HttpServletResponse response) {

        if(!(loginRequest.getDeviceType() == DeviceType.WEB) && !loginRequest.getDeviceType().equals(DeviceType.MOBILE)) {
            throw new BadRequestException("Invalid device type");
        }

        User user = userRepository.findUserByEmail(loginRequest.getEmail()).orElseThrow(
                () -> new ResourceNotFoundException("User email not found")
        );

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            if(loginRequest.getExistingRefreshToken() != null && !loginRequest.getExistingRefreshToken().isEmpty())  {

                String existingToken = tokenHasher.hmacSha256(loginRequest.getExistingRefreshToken());

                redisRefreshTokenService.revokeToken(existingToken);
            }

            if(loginRequest.getDeviceType().equals(DeviceType.WEB)) {
                tokenService.createNewTokens(response, user, DeviceType.WEB);
                return null;
            } else {
                return tokenService.createNewTokens(response, user, DeviceType.MOBILE);
            }

        } catch (AuthenticationException ex) {

            if (ex instanceof BadCredentialsException) {
                throw new InvalidCredentialsException("Invalid credentials provided");
            }
            // Log or return the specific error
            throw new BadRequestException("Authentication failed: " + ex.getMessage());
        }

    }


}
