package com.example.demo.service;

import com.example.demo.Role;
import com.example.demo.dto.*;
import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;

        if(registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }
        else if(registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }
        else if(registrationId.equals("kakao")) {
            oAuth2Response = new KakaoResponse(oAuth2User.getAttributes());
        }
        else if(registrationId.equals("facebook")) {
            oAuth2Response = new FacebookResponse(oAuth2User.getAttributes());
        }

        String providerId = oAuth2Response.getProvider() + "_" + oAuth2Response.getProviderId();
        String email = oAuth2Response.getEmail();
        String name = oAuth2Response.getName();

        User existData = userRepository.findByProviderId(providerId);
        Role role = null;

        if(existData == null) {
            User user = new User();
            user.setEmail(email);
            user.setName(name);
            // 이메일 앞부분을 username으로 사용
            String username = email.substring(0, email.indexOf("@"));
            user.setUsername(username);
            user.setProvider(registrationId);
            user.setProvider_id(providerId);
            user.setRole(Role.USER);

            userRepository.save(user);
            role = Role.USER;
        }
        else {
            role = existData.getRole();
            existData.setEmail(oAuth2Response.getEmail());
            // 기존 사용자의 username도 업데이트
            String username = email.substring(0, email.indexOf("@"));
            existData.setUsername(username);
            userRepository.save(existData);
        }

        return new CustomOAuth2User(oAuth2Response, role);
    }
}