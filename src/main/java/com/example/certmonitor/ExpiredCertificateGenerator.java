package com.example.certmonitor;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.KeyStore;

public class ExpiredCertificateGenerator {

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Creating expired certificate...");

        // Generate RSA 2048 key pair
        KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Certificate was valid in the past
        Date notBefore =
                new Date(System.currentTimeMillis()
                        - (10L * 24 * 60 * 60 * 1000));

        Date notAfter =
                new Date(System.currentTimeMillis()
                        - (5L * 24 * 60 * 60 * 1000));

        X500Name subject =
                new X500Name(
                        "CN=Expired Certificate,O=Certificate Monitoring,C=IN");

        BigInteger serialNumber =
                BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(
                        subject,
                        serialNumber,
                        notBefore,
                        notAfter,
                        subject,
                        keyPair.getPublic());

        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC")
                        .build(keyPair.getPrivate());

        X509CertificateHolder certificateHolder =
                certificateBuilder.build(signer);

        X509Certificate certificate =
                new JcaX509CertificateConverter()
                        .setProvider("BC")
                        .getCertificate(certificateHolder);

        // Create PKCS12 keystore
        KeyStore keyStore =
                KeyStore.getInstance("PKCS12");

        keyStore.load(null, null);

        keyStore.setKeyEntry(
                "expiredcertificate",
                keyPair.getPrivate(),
                "changeit".toCharArray(),
                new X509Certificate[]{certificate}
        );

        // Save certificate
        try (FileOutputStream outputStream =
                     new FileOutputStream(
                             "certificates/expired-certificate.p12")) {

            keyStore.store(
                    outputStream,
                    "changeit".toCharArray());
        }

        System.out.println();
        System.out.println("======================================");
        System.out.println("EXPIRED CERTIFICATE CREATED");
        System.out.println("======================================");
        System.out.println("File: certificates/expired-certificate.p12");
        System.out.println("Alias: expiredcertificate");
        System.out.println("Password: changeit");
        System.out.println("Algorithm: RSA");
        System.out.println("Key Size: 2048");
        System.out.println("Status: EXPIRED");
        System.out.println("======================================");
    }
}