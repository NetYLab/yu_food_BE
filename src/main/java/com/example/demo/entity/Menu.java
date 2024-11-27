package com.example.demo.entity;

import jakarta.persistence.*;
import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "menu_info")
public class Menu {
    @Id
    private Integer mid;
    
    private String mname;
    private Integer mprice;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rid")
    @JsonIgnore
    private Restaurant restaurant;

    // 기본 생성자
    public Menu() {
    }

    // 모든 필드를 포함한 생성자
    public Menu(Integer mid, String mname, Integer mprice, Restaurant restaurant) {
        this.mid = mid;
        this.mname = mname;
        this.mprice = mprice;
        this.restaurant = restaurant;
    }

    // Getter 메소드들
    public Integer getMid() {
        return mid;
    }

    public String getMname() {
        return mname;
    }

    public Integer getMprice() {
        return mprice;
    }

    public Restaurant getRestaurant() {
        return restaurant;
    }

    // Setter 메소드들
    public void setMid(Integer mid) {
        this.mid = mid;
    }

    public void setMname(String mname) {
        this.mname = mname;
    }

    public void setMprice(Integer mprice) {
        this.mprice = mprice;
    }

    public void setRestaurant(Restaurant restaurant) {
        this.restaurant = restaurant;
        if (restaurant != null && !restaurant.getMenus().contains(this)) {
            restaurant.getMenus().add(this);
        }
    }
}