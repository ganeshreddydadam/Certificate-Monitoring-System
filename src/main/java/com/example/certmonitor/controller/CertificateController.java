package com.example.certmonitor.controller;

import com.example.certmonitor.model.CertificateInfo;
import com.example.certmonitor.repository.CertificateRepository;
import com.example.certmonitor.service.AIAnalysisService;
import com.example.certmonitor.service.CertificateAIAgentService;
import com.example.certmonitor.service.CertificateScannerService;

import jakarta.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Controller
public class CertificateController {

    private final CertificateRepository certificateRepository;
    private final CertificateScannerService scannerService;
    private final AIAnalysisService aiAnalysisService;
    private final CertificateAIAgentService certificateAIAgentService;

    @Value("${certificate.repository.path}")
    private String repositoryPath;

    private static final String SCANNED_FILES_SESSION =
            "scannedCertificateFiles";

    public CertificateController(
            CertificateRepository certificateRepository,
            CertificateScannerService scannerService,
            AIAnalysisService aiAnalysisService,
            CertificateAIAgentService certificateAIAgentService) {

        this.certificateRepository = certificateRepository;
        this.scannerService = scannerService;
        this.aiAnalysisService = aiAnalysisService;
        this.certificateAIAgentService = certificateAIAgentService;
    }


    // =========================================================
    // DASHBOARD
    // =========================================================

    @GetMapping("/")
    public String dashboard(
            Model model,
            HttpSession session) {

        // Get actual certificate files from certificates folder
        List<String> certificateFiles =
                getCertificateFiles();


        // Get files that have been successfully scanned
        Set<String> scannedFileNames =
                getScannedFileNames(session);


        // Remove files which no longer exist
        scannedFileNames.retainAll(
                new HashSet<>(certificateFiles)
        );


        // Get all records from database
        List<CertificateInfo> allCertificates =
                certificateRepository.findAll();


        // Create map:
        // filename -> scanned certificate
        Map<String, CertificateInfo> scannedCertificateMap =
                new LinkedHashMap<>();


        for (CertificateInfo certificate : allCertificates) {

            String fileName =
                    certificate.getFileName();

            if (fileName == null) {
                continue;
            }


            if (scannedFileNames.contains(fileName)) {

                /*
                 * One dashboard row represents one
                 * certificate file.
                 *
                 * If the same file has multiple records,
                 * keep the first one.
                 */
                scannedCertificateMap.putIfAbsent(
                        fileName,
                        certificate
                );
            }
        }


        // =====================================================
        // SUMMARY
        // =====================================================

        long total =
                certificateFiles.size();


        long low =
                scannedCertificateMap.values()
                        .stream()
                        .filter(c ->
                                "LOW".equalsIgnoreCase(
                                        c.getRiskLevel()
                                ))
                        .count();


        long medium =
                scannedCertificateMap.values()
                        .stream()
                        .filter(c ->
                                "MEDIUM".equalsIgnoreCase(
                                        c.getRiskLevel()
                                ))
                        .count();


        long high =
                scannedCertificateMap.values()
                        .stream()
                        .filter(c ->
                                "HIGH".equalsIgnoreCase(
                                        c.getRiskLevel()
                                ))
                        .count();


        // =====================================================
        // SEND DATA TO THYMELEAF
        // =====================================================

        model.addAttribute(
                "certificateFiles",
                certificateFiles
        );

        model.addAttribute(
                "certificates",
                new ArrayList<>(scannedCertificateMap.values())
        );

        model.addAttribute(
                "scannedCertificateMap",
                scannedCertificateMap
        );

        model.addAttribute(
                "total",
                total
        );

        model.addAttribute(
                "low",
                low
        );

        model.addAttribute(
                "medium",
                medium
        );

        model.addAttribute(
                "high",
                high
        );


        return "dashboard";
    }


    // =========================================================
    // SCAN ALL CERTIFICATES
    // =========================================================

    @PostMapping("/scan")
    public String scanAll(
            HttpSession session) {

        /*
         * Existing scanner is NOT changed.
         */
        scannerService.scanCertificates();


        /*
         * After scanning, determine which files
         * actually have records in the database.
         */
        List<CertificateInfo> scannedCertificates =
                certificateRepository.findAll();


        Set<String> successfullyScanned =
                new HashSet<>();


        for (CertificateInfo certificate :
                scannedCertificates) {

            if (certificate.getFileName() != null) {

                successfullyScanned.add(
                        certificate.getFileName()
                );
            }
        }


        session.setAttribute(
                SCANNED_FILES_SESSION,
                successfullyScanned
        );


        return "redirect:/";
    }


    // =========================================================
    // SCAN ONE CERTIFICATE
    // =========================================================

    @PostMapping("/scan/{fileName}")
    public String scanOne(
            @PathVariable String fileName,
            HttpSession session) {


        /*
         * Existing scanner is used.
         */
        scannerService.scanCertificate(
                fileName
        );


        /*
         * Get current session scanned files.
         */
        Set<String> scannedFiles =
                getScannedFileNames(session);


        /*
         * Check whether this certificate
         * was successfully saved in DB.
         */
        boolean successfullyScanned =
                certificateRepository
                        .findAll()
                        .stream()
                        .anyMatch(c ->
                                fileName.equals(
                                        c.getFileName()
                                )
                        );


        if (successfullyScanned) {

            scannedFiles.add(fileName);

        } else {

            scannedFiles.remove(fileName);

        }


        session.setAttribute(
                SCANNED_FILES_SESSION,
                scannedFiles
        );


        return "redirect:/";
    }


    // =========================================================
    // AI ANALYSIS
    // =========================================================

    @GetMapping("/certificate/{id}/ai-analysis")
    public String aiAnalysis(
            @PathVariable Long id,
            Model model) {


        CertificateInfo certificate =
                certificateRepository
                        .findById(id)
                        .orElse(null);


        if (certificate == null) {

            return "redirect:/";
        }


        String analysis =
                aiAnalysisService
                        .analyzeCertificate(
                                certificate
                        );


        model.addAttribute(
                "certificate",
                certificate
        );


        model.addAttribute(
                "analysis",
                analysis
        );


        return "ai-analysis";
    }


    // =========================================================
    // CERTIFICATE AI AGENT
    // =========================================================

    @PostMapping("/ai-agent/ask")
    @ResponseBody
    public String askCertificateAI(
            @RequestParam("question") String question) {


        return certificateAIAgentService
                .askQuestion(question);
    }


    // =========================================================
    // GET SCANNED FILES FROM SESSION
    // =========================================================

    @SuppressWarnings("unchecked")
    private Set<String> getScannedFileNames(
            HttpSession session) {


        Object value =
                session.getAttribute(
                        SCANNED_FILES_SESSION
                );


        if (value instanceof Set<?>) {

            return (Set<String>) value;
        }


        Set<String> newSet =
                new HashSet<>();


        session.setAttribute(
                SCANNED_FILES_SESSION,
                newSet
        );


        return newSet;
    }


    // =========================================================
    // GET ACTUAL CERTIFICATE FILES
    // =========================================================

    private List<String> getCertificateFiles() {

        List<String> files =
                new ArrayList<>();


        File directory =
                new File(repositoryPath);


        if (!directory.exists()
                || !directory.isDirectory()) {

            return files;
        }


        File[] certificateFiles =
                directory.listFiles();


        if (certificateFiles == null) {

            return files;
        }


        for (File file : certificateFiles) {

            if (!file.isFile()) {
                continue;
            }


            String fileName =
                    file.getName()
                            .toLowerCase();


            if (fileName.endsWith(".p12")
                    || fileName.endsWith(".pfx")
                    || fileName.endsWith(".jks")
                    || fileName.endsWith(".cer")
                    || fileName.endsWith(".crt")) {


                files.add(file.getName());
            }
        }


        files.sort(String.CASE_INSENSITIVE_ORDER);


        return files;
    }
}