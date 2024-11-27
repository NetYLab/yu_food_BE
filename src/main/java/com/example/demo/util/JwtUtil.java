package com.example.demo.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.springframework.stereotype.Component;

import java.util.Date;

import javax.crypto.SecretKey;

@Component
public class JwtUtil {
    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 86400000; // 1일

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000)) // 1일 유효
                .signWith(SECRET_KEY)
                .compact();
    }

    // JWT 토큰 검증 및 사용자 이름 추출
    public String validateTokenAndGetUsername(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY) // 서명 키 설정
                    .build()
                    .parseClaimsJws(token) // 토큰 파싱 및 검증
                    .getBody(); // 클레임 정보 가져오기

            // 토큰의 subject(사용자 이름) 반환
            return claims.getSubject();
        } catch (Exception e) {
            // 토큰 검증 실패 시 null 반환
            System.err.println("JWT 검증 실패: " + e.getMessage());
            return null;
        }
    }
}