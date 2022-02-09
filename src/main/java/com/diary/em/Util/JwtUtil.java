package com.diary.em.Util;

import java.security.Key;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class JwtUtil {
    
    private Key key;

    //외부에서(키값음 property.yml에 넣어놈) 시크릿 키 주입
    public JwtUtil(String secret){  
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    //JWT생성
    public String createToken(long id, String name) {   
        String token = Jwts.builder()
                .claim("userId",id) //키값과 벨류로 쌍으로 묶임(payload에 들어갈 부분)
                .claim("name",name) //키값과 벨류로 쌍으로 묶임(payload에 들어갈 부분)
                .signWith(key, SignatureAlgorithm.HS256)//고유한 키값을 해싱
                .compact();
        return token;
    }

    //JWT조회(?)
    public Claims getClamins(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(token)//싸인이 포함된 jwt = jws
                .getBody();
        return claims;
    }
}
