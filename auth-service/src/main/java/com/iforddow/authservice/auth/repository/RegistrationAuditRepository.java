package com.iforddow.authservice.auth.repository;

import com.iforddow.authservice.auth.entity.RegistrationAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * A repository interface for managing RegistrationAudit entities.
 * This interface extends JpaRepository to provide CRUD operations
 * and additional JPA functionalities for the RegistrationAudit entity.
 *
 * @author IFD
 * @since 2025-11-09
 * */
@Repository
public interface RegistrationAuditRepository extends JpaRepository<RegistrationAudit, UUID> {


}
