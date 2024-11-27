package com.example.demo;

import lombok.Getter;

@Getter
public enum Role {
    GUEST("ROLE_GUEST"),
    USER("ROLE_USER"),
    ADMIN("ROLE_ADMIN");

    Role(String role) {
        this.role = role;
    }
    private String role;
    
    public void setRole(String role) {
    	this.role = role;
    }
    
    public String getRole() {
    	return role;
    }
}
