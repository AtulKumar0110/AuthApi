package com.example.authapi.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${server.port}")
    private String serverPort;

    @Value("${spring.application.name}")
    private String appName;

    public void sendVerificationEmail(String toEmail, String token) {
        String verificationUrl = "http://localhost:" + serverPort + "/api/auth/verify-email?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject(appName + " - Email Verification");
        message.setText(
                "Hello,\n\n" +
                "Welcome to " + appName + "! Please click the link below to verify your email address:\n" +
                verificationUrl + "\n\n" +
                "If you didn’t request this, please ignore this email."
        );

        mailSender.send(message);
    }
}
