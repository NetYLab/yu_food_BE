package com.example.demo.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class HomeController {
    @GetMapping("/")
    public void handleRoot(HttpServletResponse response) throws IOException {
        response.sendRedirect("http://localhost:3000");
    }
}