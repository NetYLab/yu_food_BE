package com.example.demo.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.ResourceNotFoundException;
import com.example.demo.entity.*;
import com.example.demo.repository.*;

import com.example.demo.entity.Review;

@Service
public class ReviewService {

    @Autowired
    private ReviewRepository reviewRepository;

    public Review saveReview(Review review) {
        return reviewRepository.save(review);
    }

    public List<Review> getReviewsByRestaurantId(Integer rid) {
        return reviewRepository.findByRestaurantRid(rid);
    }

    public Review updateReview(Integer reviewid, Review review) {
        Review existingReview = reviewRepository.findById(reviewid)
            .orElseThrow(() -> 
            new ResourceNotFoundException("Review not found"));
        
        existingReview.setReviewstar(review.getReviewstar());
        existingReview.setContent(review.getContent());
        
        return reviewRepository.save(existingReview);
    }

    public void deleteReview(Integer reviewid) {
        reviewRepository.deleteById(reviewid);
    }
}