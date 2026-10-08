package com.example.certmonitor.service;

import com.example.certmonitor.model.CertificateInfo;
import org.springframework.stereotype.Service;

@Service
public class AIAnalysisService {

    public String analyzeCertificate(
            CertificateInfo certificate) {

        StringBuilder analysis =
                new StringBuilder();

        analysis.append("AI SECURITY ANALYSIS\n\n");

        analysis.append("Certificate: ")
                .append(certificate.getFileName())
                .append("\n\n");

        analysis.append("SECURITY SUMMARY:\n");

        if (certificate.getDaysRemaining() < 0) {

            analysis.append(
                    "The certificate has expired and "
                    + "requires renewal or replacement.\n");

        } else if (certificate.getDaysRemaining() <= 30) {

            analysis.append(
                    "The certificate is approaching "
                    + "expiration and should be renewed soon.\n");

        } else {

            analysis.append(
                    "The certificate is currently within "
                    + "its validity period.\n");
        }


        analysis.append("\nRISK REASON:\n");

        analysis.append(
                "Current rule-based risk level: ")
                .append(certificate.getRiskLevel())
                .append("\n");

        analysis.append(
                "Days remaining: ")
                .append(certificate.getDaysRemaining())
                .append("\n");

        analysis.append(
                "Chain status: ")
                .append(certificate.getChainStatus())
                .append("\n");

        analysis.append(
                "Algorithm: ")
                .append(certificate.getAlgorithm())
                .append("\n");

        analysis.append(
                "Key size: ")
                .append(certificate.getKeySize())
                .append(" bits\n");


        analysis.append("\nSECURITY FINDINGS:\n");

        if (certificate.getDaysRemaining() < 0) {

            analysis.append(
                    "• Certificate has expired.\n");

        } else if (certificate.getDaysRemaining() <= 30) {

            analysis.append(
                    "• Certificate is close to expiration.\n");
        }

        if ("INVALID".equalsIgnoreCase(
                certificate.getChainStatus())) {

            analysis.append(
                    "• Certificate chain status is INVALID.\n");

        } else if ("SELF_SIGNED".equalsIgnoreCase(
                certificate.getChainStatus())) {

            analysis.append(
                    "• Certificate is self-signed.\n");

        } else if ("NO_CHAIN".equalsIgnoreCase(
                certificate.getChainStatus())) {

            analysis.append(
                    "• Complete certificate chain "
                    + "is not available.\n");
        }


        if (certificate.getKeySize() > 0
                && certificate.getKeySize() < 2048) {

            analysis.append(
                    "• Key size is below 2048 bits.\n");
        }


        analysis.append("\nRECOMMENDED ACTIONS:\n");

        if (certificate.getDaysRemaining() < 0) {

            analysis.append(
                    "• Renew or replace the expired certificate.\n");

        } else if (certificate.getDaysRemaining() <= 30) {

            analysis.append(
                    "• Plan certificate renewal before expiration.\n");
        }

        if ("INVALID".equalsIgnoreCase(
                certificate.getChainStatus())) {

            analysis.append(
                    "• Investigate and correct the certificate "
                    + "chain configuration.\n");
        }

        if ("SELF_SIGNED".equalsIgnoreCase(
                certificate.getChainStatus())) {

            analysis.append(
                    "• Verify whether self-signed usage "
                    + "is appropriate for this environment.\n");
        }

        analysis.append(
                "• Continue monitoring certificate validity "
                + "and configuration.\n");

        return analysis.toString();
    }
}