package com.example.certmonitor.service;

import com.example.certmonitor.model.CertificateInfo;
import com.example.certmonitor.repository.CertificateRepository;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

@Service
public class CertificateAIAgentService {

    private final CertificateRepository certificateRepository;

    private final HttpClient httpClient;

    private final ObjectMapper objectMapper;

    private static final String OLLAMA_URL =
            "http://localhost:11434/api/generate";

    private static final String MODEL =
            "llama3.2";


    // ==========================================
    // CONSTRUCTOR
    // ==========================================

    public CertificateAIAgentService(
            CertificateRepository certificateRepository) {

        this.certificateRepository =
                certificateRepository;

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        this.objectMapper = new ObjectMapper();
    }


    // ==========================================
    // ASK CERTIFICATE AI
    // ==========================================

    public String askQuestion(String question) {

        if (question == null ||
                question.trim().isEmpty()) {

            return "Please enter a certificate-related question.";
        }


        List<CertificateInfo> certificates =
                certificateRepository.findAll();


        if (certificates.isEmpty()) {

            return "There are no scanned certificates available in the system.";
        }


        String certificateData =
                buildCertificateData(certificates);


        String prompt =
                buildPrompt(
                        question,
                        certificateData);


        try {

            return callOllama(prompt);

        } catch (Exception e) {

            e.printStackTrace();

            return "Certificate AI Agent error: "
                    + e.getMessage();
        }
    }


    // ==========================================
    // CALL OLLAMA
    // ==========================================

    private String callOllama(
            String prompt) throws Exception {

        String requestBody =
                objectMapper.writeValueAsString(
                        new OllamaRequest(
                                MODEL,
                                prompt,
                                false));


        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(OLLAMA_URL))
                        .timeout(Duration.ofMinutes(5))
                        .header(
                                "Content-Type",
                                "application/json")
                        .POST(
                                HttpRequest.BodyPublishers
                                        .ofString(requestBody))
                        .build();


        HttpResponse<String> response =
                httpClient.send(
                        request,
                        HttpResponse.BodyHandlers
                                .ofString());


        if (response.statusCode() != 200) {

            return "Ollama returned HTTP status "
                    + response.statusCode()
                    + ": "
                    + response.body();
        }


        JsonNode jsonResponse =
                objectMapper.readTree(
                        response.body());


        JsonNode responseNode =
                jsonResponse.get("response");


        if (responseNode == null ||
                responseNode.isNull()) {

            return "Ollama did not return an AI response.";
        }


        return responseNode.asText();
    }


    // ==========================================
    // BUILD CERTIFICATE DATA
    // ==========================================

    private String buildCertificateData(
            List<CertificateInfo> certificates) {

        StringBuilder data =
                new StringBuilder();


        data.append(
                "SCANNED CERTIFICATES FROM DATABASE\n");

        data.append(
                "====================================\n\n");


        for (CertificateInfo certificate :
                certificates) {

            data.append(
                    "Certificate ID: ")
                    .append(certificate.getId())
                    .append("\n");


            data.append(
                    "File Name: ")
                    .append(safe(
                            certificate.getFileName()))
                    .append("\n");


            data.append(
                    "Alias: ")
                    .append(safe(
                            certificate.getAlias()))
                    .append("\n");


            data.append(
                    "Subject: ")
                    .append(safe(
                            certificate.getSubject()))
                    .append("\n");


            data.append(
                    "Issuer: ")
                    .append(safe(
                            certificate.getIssuer()))
                    .append("\n");


            data.append(
                    "Algorithm: ")
                    .append(safe(
                            certificate.getAlgorithm()))
                    .append("\n");


            data.append(
                    "Signature Algorithm: ")
                    .append(safe(
                            certificate
                                    .getSignatureAlgorithm()))
                    .append("\n");


            data.append(
                    "Key Size: ")
                    .append(
                            certificate.getKeySize() != null
                                    ? certificate.getKeySize()
                                    : "Not available")
                    .append("\n");


            data.append(
                    "Valid From: ")
                    .append(
                            certificate.getValidFrom())
                    .append("\n");


            data.append(
                    "Valid Until: ")
                    .append(
                            certificate.getValidUntil())
                    .append("\n");


            data.append(
                    "Validity Days: ")
                    .append(
                            certificate.getValidityDays())
                    .append("\n");


            data.append(
                    "Days Remaining: ")
                    .append(
                            certificate.getDaysRemaining())
                    .append("\n");


            data.append(
                    "Chain Status: ")
                    .append(
                            safe(
                                    certificate
                                            .getChainStatus()))
                    .append("\n");


            data.append(
                    "Risk Level: ")
                    .append(
                            safe(
                                    certificate
                                            .getRiskLevel()))
                    .append("\n");


            data.append(
                    "Scanned At: ")
                    .append(
                            certificate.getScannedAt())
                    .append("\n");


            data.append(
                    "------------------------------------\n\n");
        }


        return data.toString();
    }


    // ==========================================
    // BUILD AI PROMPT
    // ==========================================

    private String buildPrompt(
            String question,
            String certificateData) {

        return """
                You are the Certificate Security AI Agent
                for a Certificate Monitoring System.

                Your purpose is ONLY to answer questions
                related to digital certificates and the
                certificates monitored by this application.

                =========================================
                STRICT RULES
                =========================================

                1. Use ONLY the certificate information
                   supplied below as the source of truth
                   for monitored certificates.

                2. Never invent certificate information.

                3. Never guess:
                   - expiry dates
                   - issuer
                   - subject
                   - algorithm
                   - key size
                   - signature algorithm
                   - chain status
                   - risk level
                   - validity
                   - days remaining

                4. If information is not available,
                   explicitly say that it is not available.

                5. You may explain general concepts such as:
                   - X.509
                   - PKCS12
                   - PFX
                   - certificate expiry
                   - certificate chain
                   - root CA
                   - intermediate CA
                   - issuer
                   - subject
                   - RSA
                   - EC
                   - key size
                   - signature algorithm
                   - self-signed certificates
                   - certificate validity
                   - certificate security
                   - certificate monitoring
                   - certificate lifecycle

                6. When the user asks about a particular
                   certificate, use the exact information
                   supplied for that certificate.

                7. When comparing certificates, compare only
                   certificates present in the supplied data.

                8. Do not create a new risk classification.
                   Use the Risk Level supplied by the
                   monitoring system.

                9. If asked why a certificate has a risk
                   level, explain the actual properties
                   supplied by the monitoring system.

                10. If the question is unrelated to
                    certificates, respond exactly:

                I can only answer questions related to
                digital certificates and the certificates
                monitored by this system.

                =========================================
                DATABASE CERTIFICATE INFORMATION
                =========================================

                """ + certificateData + """

                =========================================
                USER QUESTION
                =========================================

                """ + question + """

                =========================================
                ANSWER
                =========================================

                Give a clear and accurate answer.
                Use the actual certificate information
                supplied above.
                """;
    }


    // ==========================================
    // SAFE STRING
    // ==========================================

    private String safe(String value) {

        return value != null
                ? value
                : "Not available";
    }


    // ==========================================
    // OLLAMA REQUEST CLASS
    // ==========================================

    private static class OllamaRequest {

        public String model;

        public String prompt;

        public boolean stream;


        public OllamaRequest(
                String model,
                String prompt,
                boolean stream) {

            this.model = model;
            this.prompt = prompt;
            this.stream = stream;
        }
    }
}