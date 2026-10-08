package com.example.certmonitor.repository;

import com.example.certmonitor.model.CertificateAlert;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateAlertRepository
        extends JpaRepository<CertificateAlert, Long> {
}