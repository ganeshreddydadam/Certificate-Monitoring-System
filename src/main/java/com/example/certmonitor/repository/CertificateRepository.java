package com.example.certmonitor.repository;

import com.example.certmonitor.model.CertificateInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CertificateRepository
        extends JpaRepository<CertificateInfo, Long> {

    Optional<CertificateInfo> findByFileNameAndAlias(
            String fileName,
            String alias);
}