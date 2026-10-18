package org.example.identityservice.service;

import org.example.identityservice.entity.User;
import org.example.identityservice.repository.UserRepository;

import org.springframework.http.HttpStatus;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // =====================================
    // BÀI 1: ĐĂNG KÝ
    // =====================================

    public User register(String username, String password) {

        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Username và password không được để trống"
            );
        }

        if (userRepository.existsByUsername(username)) {

            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Username đã tồn tại"
            );
        }

        User user = new User();

        user.setId(UUID.randomUUID().toString());
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("USER");

        return userRepository.save(user);
    }

    // =====================================
    // BÀI 3: XÁC THỰC ĐĂNG NHẬP
    // =====================================

    public User authenticate(String username, String password) {

        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {

            throw new BadCredentialsException("Bad credentials");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new BadCredentialsException("Bad credentials")
                );

        // So sánh password bằng BCrypt
        if (!passwordEncoder.matches(
                password,
                user.getPassword()
        )) {

            throw new BadCredentialsException("Bad credentials");
        }

        // Trả User đã xác thực thành công
        return user;
    }
}
