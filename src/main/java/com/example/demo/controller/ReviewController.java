package com.example.demo.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.example.demo.ResourceNotFoundException;
import com.example.demo.entity.Review;
import com.example.demo.service.*;

@RestController
@RequestMapping("/api/review_info")
@CrossOrigin(origins = "http://localhost:3000")
public class ReviewController {
    @Autowired
    private ReviewService reviewService;
    
    @Autowired
    private StorageService storageService;

    @PostMapping
    public ResponseEntity<Review> createReview(
            @RequestParam("reviewstar") Integer reviewstar,
            @RequestParam("content") String content,
            @RequestParam("rid") Integer rid,
            @RequestParam(value = "image", required = false) MultipartFile image) {
        
        Review review = new Review();
        review.setReviewstar(reviewstar);
        review.setContent(content);
        review.setRid(rid);
        
        if (image != null && !image.isEmpty()) {
            String filename = storageService.store(image);
            review.setImageUrl(filename);
        }
        
        Review savedReview = reviewService.saveReview(review);
        return new ResponseEntity<>(savedReview, HttpStatus.CREATED);
    }

    // 특정 식당의 모든 리뷰 조회
    @GetMapping("/restaurant/{rid}")
    public ResponseEntity<List<Review>> getReviewsByRestaurant(@PathVariable("rid") Integer rid) {
        try {
            List<Review> reviews = reviewService.getReviewsByRestaurantId(rid);
            return ResponseEntity.ok(reviews);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // 리뷰 수정
    @PutMapping("/{reviewid}")
    public ResponseEntity<Review> updateReview(@PathVariable("reviewid") Integer reviewid, 
                                             @RequestBody Review review) {
        try {
            Review updatedReview = reviewService.updateReview(reviewid, review);
            return ResponseEntity.ok(updatedReview);
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.notFound().build();
        }
    }

    // 리뷰 삭제
    @DeleteMapping("/{reviewid}")
    public ResponseEntity<Void> deleteReview(@PathVariable("reviewid") Integer reviewid) {
        try {
            reviewService.deleteReview(reviewid);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}