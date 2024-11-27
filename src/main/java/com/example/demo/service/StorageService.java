package com.example.demo.service;

import org.springframework.web.multipart.MultipartFile;

public interface StorageService {
    String store(MultipartFile file);
    void init();
    void deleteFile(String filename);
}