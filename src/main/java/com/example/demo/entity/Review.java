package com.example.demo.entity;
import jakarta.persistence.*;

@Entity
@Table(name = "review_info")
public class Review {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer reviewid;
    private Integer reviewstar;
    private String content;
    private Integer userid;
    
    @Column(name = "imageUrl")
    private String imageUrl;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rid")
    private Restaurant restaurant;
    
    // 기본 생성자 추가
    public Review() {
        this.userid = 0;
        this.reviewstar = 0;
        this.content = "";
    }
    
    public void setReviewid(Integer reviewid) {
        this.reviewid = reviewid;
    }
    
    public Integer getReviewid() { // int에서 Integer로 변경
        return reviewid;
    }
    
    public void setReviewstar(Integer reviewstar) {
        this.reviewstar = reviewstar != null ? reviewstar : 0;
    }
    
    public Integer getReviewstar() { // int에서 Integer로 변경
        return reviewstar != null ? reviewstar : 0;
    }
    
    public void setContent(String content) {
        this.content = content != null ? content : "";
    }
    
    public String getContent() {
        return content != null ? content : "";
    }
    
    public void setRid(Integer rid) {
        if (this.restaurant == null) {
            this.restaurant = new Restaurant();
        }
        this.restaurant.setRid(rid);
    }
    
    public Integer getRid() {
        return this.restaurant != null ? this.restaurant.getRid() : null;
    }
    
    public void setUserid(Integer userid) {
        this.userid = userid != null ? userid : 0;
    }
    
    public Integer getUserid() {
        return userid != null ? userid : 0;
    }

    public void setRestaurant(Restaurant restaurant) {
        this.restaurant = restaurant;
    }

    public Restaurant getRestaurant() {
        return this.restaurant;
    }
    
    public String getImageUrl() {
        return imageUrl;
    }
    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }
}