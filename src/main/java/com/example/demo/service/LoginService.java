package com.example.demo.service;

import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class LoginService {

    @Autowired
    private UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public boolean authenticateUser(String email, String password) {
        // DB에서 이메일로 사용자 검색
        return userRepository.findByEmail(email)
                .map(user -> passwordEncoder.matches(password, user.getPassword())) // 비밀번호 비교
                .orElse(false); // 사용자 정보가 없을 경우 false 반환
    }
}