package com.diary.em.RestController;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import com.diary.em.Configuration.JwtTokenProvider;
import com.diary.em.Entity.RefreshToken;
import com.diary.em.Entity.User;
import com.diary.em.Repository.TokenRepository;
import com.diary.em.Repository.UserRepository;
import com.diary.em.Service.RedisService;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class UserController {
    
    // 토큰 유효시간 30분
    private long tokenValidTime = 30 * 60 * 1000L;

    // 리프레시 토큰 유효시간 | 1m
    private long refreshTokenValidTime = 1 * 60 * 1000L;
    
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final RedisService redisService;
    

    // 회원가입
    @PostMapping("/join")
    public Long join(@RequestBody Map<String, String> user) {
        return userRepository.save(User.builder()
                .email(user.get("email"))
                .password(passwordEncoder.encode(user.get("password")))
                .roles(Collections.singletonList("ROLE_USER")) // 최초 가입시 USER 로 설정
                .build()).getId();
    }

    // 로그인
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody Map<String, String> user, HttpServletResponse response) {
        
        User member = userRepository.findByEmail(user.get("email"))
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));
        
        if (!passwordEncoder.matches(user.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
        }
         // 어세스, 리프레시 토큰 발급 및 헤더 설정
         String accessToken = jwtTokenProvider.createToken(member.getUsername(), member.getRoles(), tokenValidTime);
         String refreshToken = jwtTokenProvider.createToken(member.getEmail(), member.getRoles(), refreshTokenValidTime);

         jwtTokenProvider.setHeaderAccessToken(response, accessToken);
         jwtTokenProvider.setHeaderRefreshToken(response, refreshToken);
         
        // 리프레시 토큰 H2 저장소에 저장
        //  tokenRepository.save(new RefreshToken(refreshToken));

        // Redis 인메모리에 리프레시 토큰 저장
        redisService.setValues(refreshToken, member.getEmail());
 
        
        return ResponseEntity.ok().body("accessToken:" + accessToken);
    }
}
