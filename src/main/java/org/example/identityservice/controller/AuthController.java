package org.example.identityservice.controller;

import org.example.identityservice.entity.User;
import org.example.identityservice.entity.RefreshToken;

import org.example.identityservice.repository.UserRepository;

import org.example.identityservice.service.AuthService;
import org.example.identityservice.service.RefreshTokenService;

import org.example.identityservice.util.JwtUtil;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.security.authentication.BadCredentialsException;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    public AuthController(
            AuthService authService,
            UserRepository userRepository,
            JwtUtil jwtUtil,
            RefreshTokenService refreshTokenService
    ) {
        this.authService = authService;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
    }

    // =====================================
    // BÀI 1: REGISTER
    // =====================================

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @RequestBody RegisterRequest request
    ) {

        User user = authService.register(
                request.username(),
                request.password()
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(
                        new RegisterResponse(
                                user.getId(),
                                user.getUsername(),
                                user.getRole()
                        )
                );
    }

    // =====================================
    // BÀI 2: TEST ACCESS TOKEN
    // =====================================

    @GetMapping(
            value = "/test-token",
            produces = MediaType.TEXT_PLAIN_VALUE
    )
    public String testToken(
            @RequestParam String username
    ) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "Không tìm thấy User: " + username
                        )
                );

        return jwtUtil.generateAccessToken(user);
    }

    // =====================================
    // BÀI MỚI: LOGIN TRẢ 2 TOKEN
    // =====================================

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody LoginRequest request
    ) {

        // 1. Xác thực username/password
        User user = authService.authenticate(
                request.username(),
                request.password()
        );

        // 2. Tạo Access Token
        String accessToken =
                jwtUtil.generateAccessToken(user);

        // 3. Tạo Refresh Token và lưu PostgreSQL
        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(
                        user.getId()
                );

        // 4. Trả về cả hai token
        return ResponseEntity.ok(
                new LoginResponse(
                        accessToken,
                        refreshToken.getToken()
                )
        );
    }

    // =====================================
    // XỬ LÝ LỖI ĐĂNG NHẬP
    // =====================================

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(
            BadCredentialsException exception
    ) {

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(
                        new ErrorResponse("Bad credentials")
                );
    }

    // =====================================
    // DTO
    // =====================================

    public record RegisterRequest(
            String username,
            String password
    ) {
    }

    public record RegisterResponse(
            String id,
            String username,
            String role
    ) {
    }

    public record LoginRequest(
            String username,
            String password
    ) {
    }

    public record LoginResponse(
            String accessToken,
            String refreshToken
    ) {
    }

    public record ErrorResponse(
            String message
    ) {
    }
}