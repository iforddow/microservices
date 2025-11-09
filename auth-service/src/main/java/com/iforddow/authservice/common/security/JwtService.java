package com.iforddow.authservice.common.security;

import com.iforddow.authservice.auth.entity.User;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;

/**
 * A service for handling JWT (JSON Web Token) operations.
 * This service provides methods to generate, validate,
 * and extract information from JWT tokens.
 *
 * @author IFD
 * @since 2025-06-15
 * */
@Service
public class JwtService {

    // The secret key used to sign the JWT tokens
    @Value("${jwt.secret}")
    public String jwtSecret;

    // The expiration time for the access token in milliseconds
    @Value("${jwt.access_expiration}")
    public int jwtExpirationMs;

    // The expiration time for the session token in milliseconds
    @Value("${jwt.session_expiration}")
    public int jwtSessionExpirationMs;

    /**
     * A method to generate a JWT token for a user.
     *
     * @param user The username for which to generate the JWT token.
     * @return A JWT token as a String.
     *
     * @author IFD
     * @since 2025-06-15
     * */
    public String generateJwtToken(User user) {
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("email", user.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(getKey())
                .compact();
    }

    /**
     * A method to generate a session token for a user.
     *
     * @param user The username for which to generate the session token.
     * @return A JWT session token as a String.
     *
     * @author IFD
     * @since  2025-06-15
     * */
    public String generateSessionToken(User user) {
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("email", user.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtSessionExpirationMs))
                .signWith(getKey())
                .compact();
    }

    /**
     * A method to extract the users id from a JWT token.
     *
     * @param token The JWT token from which to extract the user id.
     * @return The user id extracted from the token.
     *
     * @author IFD
     * @since 2025-06-15
     * */
    public String getUserIdFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey()).build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
    * A method to extract the expiration time from a JWT token.
    *
    * @param token The JWT token from which to extract the expiration time.
    * @return The expiration time as an Instant.
    *
    * @author IFD
    * @since 2025-11-04
    * */
    public Instant getExpirationFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey()).build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration().toInstant();
    }

    /**
     * A method to validate a JWT token.
     *
     * @param token The JWT token to validate.
     * @return true if the token is valid, false otherwise.
     *
     * @author IFD
     * @since 2025-06-15
     * */
    public boolean validateJwtToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SecurityException e) {
            System.out.println("Invalid JWT signature: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT token: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.out.println("JWT token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("JWT token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("JWT claims string is empty: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("JWT validation error: " + e.getMessage());
        }
        return false;
    }

    /**
     * A method to get the signing key for JWT tokens.
     *
     * @return The signing key as a Key object.
     *
     * @author IFD
     * @since 2025-06-15
     * */
    public Key getKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }


}

