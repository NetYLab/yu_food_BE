package com.example.demo.service;

import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.regex.Pattern;

@Service
public class ProfileService {

    @Autowired
    private UserRepository userRepository;

    private static final Pattern NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9]{3,}$");

    @Transactional
    public User updateProfile(String email, String username, String name, String newEmail) {
        if (!isValidName(name)) {
            throw new ProfileValidationException("닉네임은 알파벳과 숫자 조합으로 3자 이상이어야 합니다.");
        }

        if (username == null || username.trim().isEmpty()) {
            throw new ProfileValidationException("사용자 이름은 필수 입력값입니다.");
        }

        if (email == null || email.trim().isEmpty()) {
            throw new ProfileValidationException("이메일은 필수 입력값입니다.");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ProfileValidationException("사용자를 찾을 수 없습니다."));

        // Check if name is already taken by another user
        userRepository.findByName(name)
                .ifPresent(existingUser -> {
                    if (!existingUser.getEmail().equals(email)) {
                        throw new ProfileValidationException("이미 사용 중인 닉네임입니다.");
                    }
                });

        user.setUsername(username);
        user.setName(name);
        user.setEmail(newEmail);

        return userRepository.save(user);
    }

    private boolean isValidName(String name) {
        return name != null && NAME_PATTERN.matcher(name).matches();
    }

    class ProfileValidationException extends RuntimeException {
        public ProfileValidationException(String message) {
            super(message);
        }
    }
}