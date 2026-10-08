package com.example.certmonitor.service;

import org.springframework.stereotype.Service;

@Service
public class RiskClassificationService {

    public String calculateRisk(
            long daysRemaining,
            String algorithm,
            int keySize,
            String chainStatus) {

        // HIGH RISK

        if (daysRemaining < 0) {
            return "HIGH";
        }

        if ("INVALID".equalsIgnoreCase(chainStatus)) {
            return "HIGH";
        }

        if ("RSA".equalsIgnoreCase(algorithm)
                && keySize > 0
                && keySize < 2048) {

            return "HIGH";
        }

        if (daysRemaining <= 30) {
            return "HIGH";
        }

        // MEDIUM RISK

        if (daysRemaining <= 90) {
            return "MEDIUM";
        }

        if ("SELF_SIGNED"
                .equalsIgnoreCase(chainStatus)) {

            return "MEDIUM";
        }

        // LOW RISK

        return "LOW";
    }
}