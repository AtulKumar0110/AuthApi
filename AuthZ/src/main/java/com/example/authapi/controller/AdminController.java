package com.example.authapi.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // Endpoint accessible only by ROLE_ADMIN
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public String getAllUsers() {
        return "List of users (Admins only)";
    }

    // Another protected admin or manager endpoint
    @GetMapping("/admin-or-manager")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public String adminOrManagerAccess() {
        return "Accessible by Admin or Manager";
    }
}
