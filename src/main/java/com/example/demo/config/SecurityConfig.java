//package com.example.demo.config;
//
//import com.example.demo.service.CustomOAuth2UserService;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//    private final CustomOAuth2UserService customOAuth2UserService;
//
//    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService) {
//        this.customOAuth2UserService = customOAuth2UserService;
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf(csrf -> csrf.disable())
//                .cors(cors -> cors.configure(http))
//                .authorizeHttpRequests(auth ->
//                        auth.requestMatchers(
//                                        new AntPathRequestMatcher("/"),
//                                        new AntPathRequestMatcher("/login"),
//                                        new AntPathRequestMatcher("/oauth2/**"),
//                                        new AntPathRequestMatcher("/api/**")
//                                ).permitAll()
//                                .anyRequest().authenticated()
//                )
//                .oauth2Login(oauth2 ->
//                        oauth2.userInfoEndpoint(userInfo ->
//                                        userInfo.userService(customOAuth2UserService)
//                                )
//                                .successHandler((request, response, authentication) -> {
//                                    response.sendRedirect("http://localhost:3000");
//                                })
//                                .failureHandler((request, response, exception) -> {
//                                    response.sendRedirect("http://localhost:3000/login?error=true");
//                                })
//                );
//
//        return http.build();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
//        return authenticationConfiguration.getAuthenticationManager();
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//}

package com.example.demo.config;

import com.example.demo.dto.CustomOAuth2User;
import com.example.demo.oauth2.SocialClientRegistration;
import com.example.demo.service.CustomOAuth2UserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

@Configuration
public class SecurityConfig {
    private final CustomOAuth2UserService customOAuth2UserService;
    private final SocialClientRegistration socialClientRegistration;
    private final JwtProperties jwtProperties;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService,
                          SocialClientRegistration socialClientRegistration,
                          JwtProperties jwtProperties) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.socialClientRegistration = socialClientRegistration;
        this.jwtProperties = jwtProperties;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class) // JWT 필터 추가
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/api/yufood/**",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/login",
                                "/signup",
                                "/api/users/**",
                                "/restaurant/**",
                                "/qna/view/**",
                                "/oauth2/**",
                                "/login/oauth2/code/**",
                                "/oauth2/code/**"
                        ).permitAll()
                        .requestMatchers(
                                "/api/profile/**", // profile API는 인증 필요
                                "/qna/write/**",
                                "/review/write/**"
                        ).authenticated()
                        .anyRequest().permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler((request, response, authentication) -> {
                            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

                            String token = Jwts.builder()
                                    .setSubject(oAuth2User.getEmail()) // email을 subject로 사용
                                    .claim("role", oAuth2User.getRole())
                                    .setIssuedAt(new Date())
                                    .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                                    .signWith(jwtProperties.getSigningKey())
                                    .compact();

                            Cookie cookie = new Cookie("AUTH-TOKEN", token);
                            cookie.setPath("/");
                            cookie.setHttpOnly(true);
                            cookie.setMaxAge(86400);
                            response.addCookie(cookie);

                            response.sendRedirect("http://localhost:3000");
                        })
                );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(Arrays.asList("Set-Cookie"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // JWT 토큰 생성 메서드 추가
    private String generateToken(CustomOAuth2User user) {
        // JWT 토큰 생성 로직 구현
        // 예시:
        return Jwts.builder()
                .setSubject(user.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1시간
                .signWith(getSigningKey())
                .compact();
    }

    private Key getSigningKey() {
        // JWT 시크릿 키 설정
        String secret = "your-secret-key"; // 실제 환경에서는 설정 파일에서 가져오기
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Bean
    public InMemoryClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = Arrays.asList(
                socialClientRegistration.googleClientRegistration(),
                socialClientRegistration.naverClientRegistration(),
                socialClientRegistration.kakaoClientRegistration(),
                socialClientRegistration.facebookClientRegistration()
        );
        return new InMemoryClientRegistrationRepository(registrations);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}