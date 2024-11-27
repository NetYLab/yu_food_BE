package com.example.demo.oauth2;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.stereotype.Component;

@Component
public class SocialClientRegistration {

    public ClientRegistration naverClientRegistration() {

        return ClientRegistration.withRegistrationId("naver")
                .clientId("SLeTTfhsEYCGuE_dVJJ4")
                .clientSecret("1i9L26jns7")
                .redirectUri("http://localhost:8080/login/oauth2/code/naver")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope("name", "email")
                .authorizationUri("https://nid.naver.com/oauth2.0/authorize")
                .tokenUri("https://nid.naver.com/oauth2.0/token")
                .userInfoUri("https://openapi.naver.com/v1/nid/me")
                .userNameAttributeName("response")
                .build();
    }

    public ClientRegistration googleClientRegistration() {

        return ClientRegistration.withRegistrationId("google")
                .clientId("1014833639656-5ttut4am78mtltg7vcuj4o4tvg24hvf8.apps.googleusercontent.com")
                .clientSecret("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")
                .redirectUri("http://localhost:8080/login/oauth2/code/google")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope("profile", "email")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .issuerUri("https://accounts.google.com")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .build();
    }

    public ClientRegistration kakaoClientRegistration() {
        return ClientRegistration.withRegistrationId("kakao")
                .clientId("b4f76bbf0abeacb0deb048cbb15f10e0")
                .clientSecret("BCE1JE5tdGCDGDPPiXFgEnEenHa9xOGG")
                .redirectUri("http://localhost:8080/login/oauth2/code/kakao")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope("profile_nickname", "profile_image", "account_email")  // scope 수정
                .authorizationUri("https://kauth.kakao.com/oauth/authorize")
                .tokenUri("https://kauth.kakao.com/oauth/token")
                .userInfoUri("https://kapi.kakao.com/v2/user/me")
                .userNameAttributeName("id")
                .clientName("Kakao")  // clientName 추가
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)  // 인증 방식 추가
                .build();
    }

    public ClientRegistration facebookClientRegistration() {

        return ClientRegistration.withRegistrationId("facebook")
                .clientId("875122917130764")
                .clientSecret("db88a990bcd67ba1b994dfe29b378b5c")
                .redirectUri("http://localhost:8080/login/oauth2/code/facebook")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope("public_profile", "email")
                .authorizationUri("https://www.facebook.com/v2.8/dialog/oauth")
                .tokenUri("https://graph.facebook.com/v2.8/oauth/access_token")
                .userInfoUri("https://graph.facebook.com/me?fields=id,name,email")
                .userNameAttributeName("id")
                .build();
    }
}