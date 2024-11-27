package com.example.demo.service;

import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MyService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public MyService(UserRepository userRepository, PasswordEncoder passwordEncoder){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Boolean isMatch(String rawPassword, String encodedPassword){
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    public User getUserByUsername(String username){
        Optional<User> user = userRepository.findByUsername(username);
        if(user.isPresent())
            return user.get();
        else{
            throw new IllegalArgumentException("해당 사용자는 없습니다.");
        }
    }

    public User getUserByEmail(String email){
        Optional<User> user = userRepository.findByEmail(email);
        if(user.isPresent())
            return user.get();
        else{
            throw new IllegalArgumentException("해당 사용자는 없습니다.");
        }
    }

    // 정보 수정(비밀번호)
    public User update(User user, String newPassword){
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        return user;
    }

    // 이메일 찾기
    public Optional<String> findEmailByName(String name){
        Optional<User> user = userRepository.findByName(name);
        if(user.isPresent()){
            return Optional.of(user.get().getEmail());
        }
        return Optional.empty();
    }
}
