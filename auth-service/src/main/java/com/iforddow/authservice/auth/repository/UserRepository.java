package com.iforddow.authservice.auth.repository;

import com.iforddow.authservice.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
* A repository interface for managing User entities.
* This interface extends JpaRepository to provide CRUD operations
* and additional JPA functionalities for the User entity.
*
* @author IFD
* @since 2025-11-09
* */
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findUserByEmail(String email);

}
