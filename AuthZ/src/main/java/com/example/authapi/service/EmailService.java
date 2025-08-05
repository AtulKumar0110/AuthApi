package com.example.authapi.service;

public interface EmailService {
    void sendEmail(String to, String subject, String body);
}
