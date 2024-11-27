package com.example.demo.controller;

import com.example.demo.dto.JoinForm;
import com.example.demo.service.JoinService;
import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class JoinController {

    private static final Logger logger = LoggerFactory.getLogger(JoinController.class);

    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public ResponseEntity<?> join(@Valid @RequestBody JoinForm joinForm, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            for (FieldError error : bindingResult.getFieldErrors()) {
                errors.put(error.getField(), error.getDefaultMessage());
            }
            return ResponseEntity.badRequest().body(errors);
        }

        if (!joinForm.getPassword().equals(joinForm.getPasswordRepeated())) {
            return ResponseEntity.badRequest().body(Map.of("passwordError", "Passwords do not match."));
        }

        try {
            joinService.joinProcess(joinForm.getUsername(), joinForm.getEmail(), joinForm.getPassword());
        } catch (DataIntegrityViolationException e) {
            logger.error("User registration failed: Duplicate username", e);
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "Username or email already exists."));
        } catch (Exception e) {
            logger.error("Unexpected error during user registration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Internal server error."));
        }

        return ResponseEntity.ok(Map.of("message", "User registered successfully."));
    }
}