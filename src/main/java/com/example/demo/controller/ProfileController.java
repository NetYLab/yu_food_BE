package com.example.demo.controller;

import com.example.demo.entity.User;
import com.example.demo.service.ProfileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import com.example.demo.repository.UserRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

@CrossOrigin
@RestController
@RequestMapping("/api")
public class ProfileController {
    private static final Pattern NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9]{3,}$");

    private final UserRepository userRepository;
    private final ProfileService profileService;

    @Autowired
    public ProfileController(UserRepository userRepository, ProfileService profileService) {
        this.userRepository = userRepository;
        this.profileService = profileService;
    }

    @GetMapping("/profile")
    public ResponseEntity<ProfileResponse> getProfile(Authentication authentication) {
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String email = null;
        if (authentication.getPrincipal() instanceof UserDetails) {
            email = ((UserDetails) authentication.getPrincipal()).getUsername();
        } else {
            email = authentication.getName();
        }

        return userRepository.findByEmail(email)
                .map(user -> ResponseEntity.ok(new ProfileResponse(user.getUsername(), user.getName(), user.getEmail())))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(null));
    }

    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody ProfileRequest request, Authentication authentication) {
        try {
            String currentEmail = authentication.getName();
            User updatedUser = profileService.updateProfile(
                    currentEmail,
                    request.getUsername(),
                    request.getName(),
                    request.getEmail()
            );

            return ResponseEntity.ok(new ProfileResponse(
                    updatedUser.getUsername(),
                    updatedUser.getName(),
                    updatedUser.getEmail()
            ));

        } catch (ProfileValidationException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        } catch (IllegalArgumentException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "프로필 업데이트 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    private void validateProfileRequest(ProfileRequest request) {
        if (request.getName() == null || request.getName().trim().isEmpty()) {
            throw new ProfileValidationException("닉네임은 필수 입력값입니다.");
        }

        if (!NAME_PATTERN.matcher(request.getName()).matches()) {
            throw new ProfileValidationException("닉네임은 알파벳과 숫자 조합으로 3자 이상이어야 합니다.");
        }

        if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
            throw new ProfileValidationException("사용자 이름은 필수 입력값입니다.");
        }

        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            throw new ProfileValidationException("이메일은 필수 입력값입니다.");
        }

        if (!request.getEmail().matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            throw new ProfileValidationException("올바른 이메일 형식이 아닙니다.");
        }
    }

    private ResponseEntity<?> createErrorResponse(String message, HttpStatus status) {
        Map<String, String> error = new HashMap<>();
        error.put("error", message);
        return ResponseEntity.status(status).body(error);
    }

    private static class ProfileRequest {
        private String username;
        private String name;
        private String email;

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }

    private static class ProfileResponse {
        private final String username;
        private final String name;
        private final String email;

        public ProfileResponse(String username, String name, String email) {
            this.username = username;
            this.name = name;
            this.email = email;
        }

        public String getUsername() { return username; }
        public String getName() { return name; }
        public String getEmail() { return email; }
    }

    class ProfileValidationException extends RuntimeException {
    public ProfileValidationException(String message) {
            super(message);
        }
    }
}