package com.example.authapi.controller;

import com.example.authapi.dto.AuthRequest;
import com.example.authapi.dto.AuthResponse;
import com.example.authapi.entity.EmailVerificationToken;
import com.example.authapi.entity.User;
import com.example.authapi.repository.EmailVerificationTokenRepository;
import com.example.authapi.repository.UserRepository;
import com.example.authapi.service.EmailService;
import com.example.authapi.util.JwtUtil;
import com.example.authapi.util.TokenUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final EmailService emailService;

    // ✅ Register a new user
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody AuthRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return ResponseEntity.badRequest().body("Username already taken.");
        }

        User newUser = new User();
        newUser.setUsername(request.getUsername());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        newUser.setRoles(List.of("ROLE_USER"));
        newUser.setEmailVerified(false);

        userRepository.save(newUser);

        // Generate verification token and send email
        String token = UUID.randomUUID().toString();
        String tokenHash = TokenUtils.hashToken(token);

        EmailVerificationToken verificationToken = new EmailVerificationToken();
        verificationToken.setTokenHash(tokenHash);
        verificationToken.setUser(newUser);
        verificationToken.setExpiryTime(LocalDateTime.now().plusHours(1));

        emailVerificationTokenRepository.save(verificationToken);
        emailService.sendVerificationEmail(newUser.getUsername(), token);

        return ResponseEntity.ok("User registered successfully. Verification email sent.");
    }

    // ✅ Authenticate user and issue JWT
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest request) {
        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }

        UserDetails userDetails = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        String jwt = jwtUtil.generateToken(userDetails.getUsername(), roles);

        return ResponseEntity.ok(new AuthResponse(jwt));
    }

    // 🔁 Resend Email Verification
    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendEmailVerification(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        User user = userRepository.findByUsername(email).orElse(null);

        if (user == null || user.isEmailVerified()) {
            return ResponseEntity.ok("If your email is not verified, a new link will be sent.");
        }

        String token = UUID.randomUUID().toString();
        String tokenHash = TokenUtils.hashToken(token);

        EmailVerificationToken verificationToken = new EmailVerificationToken();
        verificationToken.setTokenHash(tokenHash);
        verificationToken.setUser(user);
        verificationToken.setExpiryTime(LocalDateTime.now().plusHours(1));

        emailVerificationTokenRepository.save(verificationToken);
        emailService.sendVerificationEmail(user.getUsername(), token);

        return ResponseEntity.ok("Verification email sent.");
    }

    // ✅ Verify Email Endpoint
    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam("token") String token) {
        String tokenHash = TokenUtils.hashToken(token);

        Optional<EmailVerificationToken> optionalToken =
                emailVerificationTokenRepository.findByTokenHashAndIsUsedFalse(tokenHash);

        if (optionalToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Invalid or expired token.");
        }

        EmailVerificationToken verificationToken = optionalToken.get();

        if (verificationToken.getExpiryTime().isBefore(LocalDateTime.now())) {
            return ResponseEntity.badRequest().body("Token has expired.");
        }

        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        verificationToken.setIsUsed(true);
        emailVerificationTokenRepository.save(verificationToken);

        return ResponseEntity.ok("Email verified successfully.");
    }
}
