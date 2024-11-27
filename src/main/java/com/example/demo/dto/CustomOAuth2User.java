package com.example.demo.dto;

import com.example.demo.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;

public class CustomOAuth2User implements OAuth2User {
    private OAuth2Response oAuth2Response;
    private Role role;
    private Map<String, Object> attributes;

    public CustomOAuth2User(OAuth2Response oAuth2Response, Role role) {
        this.oAuth2Response = oAuth2Response;
        this.role = role;
        // attributes 초기화
        this.attributes = new HashMap<>();
        this.attributes.put("email", oAuth2Response.getEmail());
        this.attributes.put("name", oAuth2Response.getName());
        this.attributes.put("role", role);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes != null ? attributes : new HashMap<>();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getName() {
        return oAuth2Response.getName();
    }

    public String getEmail() {
        return oAuth2Response.getEmail();
    }

    public Role getRole() {
        return role;
    }
}