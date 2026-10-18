package org.example.identityservice.service;

import org.example.identityservice.entity.RefreshToken;
import org.example.identityservice.entity.User;

import org.example.identityservice.repository.RefreshTokenRepository;
import org.example.identityservice.repository.UserRepository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final long refreshTokenExpiration;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            UserRepository userRepository,
            @Value("${app.jwt.refresh-token-expiration}")
            long refreshTokenExpiration
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    // 1. Tạo Refresh Token và lưu PostgreSQL
    @Transactional
    public RefreshToken createRefreshToken(String userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "Không tìm thấy người dùng"
                        )
                );

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUser(user);

        // Sinh chuỗi UUID ngẫu nhiên
        refreshToken.setToken(
                UUID.randomUUID().toString()
        );

        // Hết hạn sau 7 ngày
        refreshToken.setExpiryDate(
                Instant.now().plusMillis(refreshTokenExpiration)
        );

        // Lưu DB
        return refreshTokenRepository.save(refreshToken);
    }

    // 2. Kiểm tra Refresh Token đã hết hạn chưa
    public RefreshToken verifyExpiration(RefreshToken token) {

        if (!token.getExpiryDate().isAfter(Instant.now())) {

            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh Token đã hết hạn"
            );
        }

        return token;
    }
}
