package com.diary.em.Service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class CustomUserDetailService implements AuthenticationUserDetailsService<Authentication> {

    @Override  
    public UserDetails loadUserDetails(Authentication token) {  
        
        User user = (User) token.getPrincipal();  
        if (user == null) {  
            throw new PreAuthenticatedCredentialsNotFoundException("USER IS NULL");  
        }  
        
        // DB에 접근해서 직접 정보를 가져오는게 일반적입니다. 
         return new CustomUserDetails().setUser(user); //setGrantedAuthorities(user.getAuthorities());  
    }


    
}
