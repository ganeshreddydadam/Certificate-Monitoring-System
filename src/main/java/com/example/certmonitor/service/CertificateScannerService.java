package com.example.certmonitor.service;

import com.example.certmonitor.model.CertificateInfo;
import com.example.certmonitor.repository.CertificateRepository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Enumeration;

@Service
public class CertificateScannerService {

    private final CertificateRepository certificateRepository;
    private final RiskClassificationService riskService;

    @Value("${certificate.repository.path}")
    private String repositoryPath;

    @Value("${certificate.keystore.password}")
    private String keystorePassword;

    public CertificateScannerService(
            CertificateRepository certificateRepository,
            RiskClassificationService riskService) {

        this.certificateRepository = certificateRepository;
        this.riskService = riskService;
    }

    // ==========================================
    // SCAN ALL CERTIFICATES
    // ==========================================

    public void scanCertificates() {

        File repositoryFolder =
                new File(repositoryPath);

        // Do not delete database records if
        // the certificate repository itself is missing
        if (!repositoryFolder.exists()
                || !repositoryFolder.isDirectory()) {
            return;
        }

        File[] files =
                repositoryFolder.listFiles();

        if (files == null) {
            return;
        }

        // Remove previous scan results
        // so dashboard represents current repository
        certificateRepository.deleteAllInBatch();

        for (File file : files) {

            if (!file.isFile()) {
                continue;
            }

            String fileName =
                    file.getName().toLowerCase();

            try {

                // PKCS12
                if (fileName.endsWith(".p12")
                        || fileName.endsWith(".pfx")) {

                    scanPKCS12(file);
                }

                // JKS
                else if (fileName.endsWith(".jks")) {

                    scanJKS(file);
                }

                // X.509 certificate
                else if (fileName.endsWith(".cer")
                        || fileName.endsWith(".crt")) {

                    scanX509Certificate(file);
                }

            } catch (Exception e) {

                System.err.println(
                        "Could not scan "
                        + file.getName());
            }
        }
    }

    // ==========================================
    // SCAN ONE CERTIFICATE
    // ==========================================

    public void scanCertificate(
            String fileName) {

        File file =
                new File(
                        repositoryPath
                                + File.separator
                                + fileName);

        if (!file.exists() || !file.isFile()) {
            return;
        }

        try {

            String lowerName =
                    file.getName().toLowerCase();

            // PKCS12
            if (lowerName.endsWith(".p12")
                    || lowerName.endsWith(".pfx")) {

                scanPKCS12(file);
            }

            // JKS
            else if (lowerName.endsWith(".jks")) {

                scanJKS(file);
            }

            // X.509 certificate
            else if (lowerName.endsWith(".cer")
                    || lowerName.endsWith(".crt")) {

                scanX509Certificate(file);
            }

        } catch (Exception e) {

            System.err.println(
                    "Could not scan certificate: "
                            + fileName);
        }
    }

    // ==========================================
    // PKCS12
    // ==========================================

    private void scanPKCS12(File file)
            throws Exception {

        KeyStore keyStore =
                KeyStore.getInstance("PKCS12");

        try (FileInputStream inputStream =
                     new FileInputStream(file)) {

            keyStore.load(
                    inputStream,
                    keystorePassword.toCharArray());
        }

        scanKeyStore(file, keyStore);
    }

    // ==========================================
    // JKS
    // ==========================================

    private void scanJKS(File file)
            throws Exception {

        KeyStore keyStore =
                KeyStore.getInstance("JKS");

        try (FileInputStream inputStream =
                     new FileInputStream(file)) {

            keyStore.load(
                    inputStream,
                    keystorePassword.toCharArray());
        }

        scanKeyStore(file, keyStore);
    }

    // ==========================================
    // CER / CRT
    // ==========================================

    private void scanX509Certificate(File file)
            throws Exception {

        CertificateFactory certificateFactory =
                CertificateFactory.getInstance("X.509");

        X509Certificate certificate;

        try (FileInputStream inputStream =
                     new FileInputStream(file)) {

            certificate =
                    (X509Certificate)
                            certificateFactory
                                    .generateCertificate(
                                            inputStream);
        }

        /*
         * Standalone .cer/.crt files do not have
         * a Java KeyStore alias.
         *
         * We use the file name as the alias.
         */
        String alias = file.getName();

        processStandaloneCertificate(
                file,
                alias,
                certificate);
    }

    // ==========================================
    // READ CERTIFICATES FROM KEYSTORE
    // ==========================================

    private void scanKeyStore(
            File file,
            KeyStore keyStore)
            throws Exception {

        Enumeration<String> aliases =
                keyStore.aliases();

        while (aliases.hasMoreElements()) {

            String alias =
                    aliases.nextElement();

            Certificate certificate =
                    keyStore.getCertificate(alias);

            if (!(certificate
                    instanceof X509Certificate)) {

                continue;
            }

            X509Certificate x509 =
                    (X509Certificate) certificate;

            processCertificate(
                    file,
                    alias,
                    x509,
                    keyStore);
        }
    }

    // ==========================================
    // PROCESS KEYSTORE CERTIFICATE
    // ==========================================

    private void processCertificate(
            File file,
            String alias,
            X509Certificate certificate,
            KeyStore keyStore)
            throws Exception {

        CertificateInfo info =
                certificateRepository
                        .findByFileNameAndAlias(
                                file.getName(),
                                alias)
                        .orElse(
                                new CertificateInfo());

        info.setFileName(file.getName());

        info.setAlias(alias);

        info.setSubject(
                certificate
                        .getSubjectX500Principal()
                        .getName());

        info.setIssuer(
                certificate
                        .getIssuerX500Principal()
                        .getName());

        String algorithm =
                certificate
                        .getPublicKey()
                        .getAlgorithm();

        info.setAlgorithm(algorithm);

        info.setSignatureAlgorithm(
                certificate.getSigAlgName());

        int keySize =
                getKeySize(
                        certificate.getPublicKey());

        info.setKeySize(keySize);

        LocalDateTime validFrom =
                certificate
                        .getNotBefore()
                        .toInstant()
                        .atZone(
                                ZoneId.systemDefault())
                        .toLocalDateTime();

        info.setValidFrom(validFrom);

        LocalDateTime validUntil =
                certificate
                        .getNotAfter()
                        .toInstant()
                        .atZone(
                                ZoneId.systemDefault())
                        .toLocalDateTime();

        info.setValidUntil(validUntil);

        long validityDays =
                ChronoUnit.DAYS.between(
                        validFrom.toLocalDate(),
                        validUntil.toLocalDate());

        info.setValidityDays(validityDays);

        long daysRemaining =
                ChronoUnit.DAYS.between(
                        LocalDate.now(),
                        validUntil.toLocalDate());

        info.setDaysRemaining(daysRemaining);

        String chainStatus =
                checkChainStatus(
                        certificate,
                        keyStore,
                        alias);

        info.setChainStatus(chainStatus);

        String risk =
                riskService.calculateRisk(
                        daysRemaining,
                        algorithm,
                        keySize,
                        chainStatus);

        info.setRiskLevel(risk);

        info.setScannedAt(
                LocalDateTime.now());

        certificateRepository.save(info);
    }

    // ==========================================
    // PROCESS CER / CRT CERTIFICATE
    // ==========================================

    private void processStandaloneCertificate(
            File file,
            String alias,
            X509Certificate certificate)
            throws Exception {

        CertificateInfo info =
                certificateRepository
                        .findByFileNameAndAlias(
                                file.getName(),
                                alias)
                        .orElse(
                                new CertificateInfo());

        info.setFileName(file.getName());

        info.setAlias(alias);

        info.setSubject(
                certificate
                        .getSubjectX500Principal()
                        .getName());

        info.setIssuer(
                certificate
                        .getIssuerX500Principal()
                        .getName());

        String algorithm =
                certificate
                        .getPublicKey()
                        .getAlgorithm();

        info.setAlgorithm(algorithm);

        info.setSignatureAlgorithm(
                certificate.getSigAlgName());

        int keySize =
                getKeySize(
                        certificate.getPublicKey());

        info.setKeySize(keySize);

        LocalDateTime validFrom =
                certificate
                        .getNotBefore()
                        .toInstant()
                        .atZone(
                                ZoneId.systemDefault())
                        .toLocalDateTime();

        info.setValidFrom(validFrom);

        LocalDateTime validUntil =
                certificate
                        .getNotAfter()
                        .toInstant()
                        .atZone(
                                ZoneId.systemDefault())
                        .toLocalDateTime();

        info.setValidUntil(validUntil);

        long validityDays =
                ChronoUnit.DAYS.between(
                        validFrom.toLocalDate(),
                        validUntil.toLocalDate());

        info.setValidityDays(validityDays);

        long daysRemaining =
                ChronoUnit.DAYS.between(
                        LocalDate.now(),
                        validUntil.toLocalDate());

        info.setDaysRemaining(daysRemaining);

        String chainStatus =
                checkStandaloneChainStatus(
                        certificate);

        info.setChainStatus(chainStatus);

        String risk =
                riskService.calculateRisk(
                        daysRemaining,
                        algorithm,
                        keySize,
                        chainStatus);

        info.setRiskLevel(risk);

        info.setScannedAt(
                LocalDateTime.now());

        certificateRepository.save(info);
    }

    // ==========================================
    // KEY SIZE
    // ==========================================

    private int getKeySize(
            PublicKey publicKey) {

        String algorithm =
                publicKey.getAlgorithm();

        if ("RSA".equalsIgnoreCase(algorithm)) {

            java.security.interfaces.RSAPublicKey
                    rsaKey =
                    (java.security.interfaces.RSAPublicKey)
                            publicKey;

            return rsaKey
                    .getModulus()
                    .bitLength();
        }

        if ("EC".equalsIgnoreCase(algorithm)) {

            java.security.interfaces.ECPublicKey
                    ecKey =
                    (java.security.interfaces.ECPublicKey)
                            publicKey;

            return ecKey
                    .getParams()
                    .getOrder()
                    .bitLength();
        }

        if ("DSA".equalsIgnoreCase(algorithm)) {

            java.security.interfaces.DSAPublicKey
                    dsaKey =
                    (java.security.interfaces.DSAPublicKey)
                            publicKey;

            return dsaKey
                    .getParams()
                    .getP()
                    .bitLength();
        }

        return 0;
    }

    // ==========================================
    // CHAIN STATUS - KEYSTORE
    // ==========================================

    private String checkChainStatus(
            X509Certificate certificate,
            KeyStore keyStore,
            String alias) {

        try {

            certificate.checkValidity();

            Certificate[] chain =
                    keyStore
                            .getCertificateChain(alias);

            if (chain == null
                    || chain.length == 0) {

                return "NO_CHAIN";
            }

            X509Certificate[] x509Chain =
                    new X509Certificate[chain.length];

            for (int i = 0;
                 i < chain.length;
                 i++) {

                x509Chain[i] =
                        (X509Certificate) chain[i];

                x509Chain[i].checkValidity();
            }

            if (x509Chain.length == 1) {

                try {

                    x509Chain[0].verify(
                            x509Chain[0]
                                    .getPublicKey());

                    return "SELF_SIGNED";

                } catch (Exception e) {

                    return "INVALID";
                }
            }

            for (int i = 0;
                 i < x509Chain.length - 1;
                 i++) {

                x509Chain[i].verify(
                        x509Chain[i + 1]
                                .getPublicKey());
            }

            return "VALID";

        } catch (Exception e) {

            return "INVALID";
        }
    }

    // ==========================================
    // CHAIN STATUS - CER / CRT
    // ==========================================

    private String checkStandaloneChainStatus(
            X509Certificate certificate) {

        try {

            certificate.checkValidity();

            /*
             * A standalone .cer/.crt file does not
             * contain its complete certificate chain.
             *
             * Check whether the certificate itself
             * is self-signed.
             */
            certificate.verify(
                    certificate.getPublicKey());

            return "SELF_SIGNED";

        } catch (java.security.cert.CertificateExpiredException
                 | java.security.cert.CertificateNotYetValidException e) {

            /*
             * The certificate is expired/not yet valid.
             * Risk calculation will use daysRemaining.
             */
            return "INVALID";

        } catch (Exception e) {

            /*
             * The certificate is valid X.509 but its
             * complete chain is not available in the
             * standalone file.
             */
            return "NO_CHAIN";
        }
    }
}