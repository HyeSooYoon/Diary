package com.diary.em.Configuration;

import com.diary.em.Service.CustomUserDetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;

public class CustomAuthenticationProvider {

}
// public class CustomAuthenticationProvider implements AuthenticationProvider {
    
//     @Autowired
//     private UserDetailsService userDeSer;
 
//     @SuppressWarnings("unchecked")
//     @Override
//     public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
//         String username = (String) authentication.getPrincipal();
//         String password = (String) authentication.getCredentials();
        
//         CustomUserDetails user = (CustomUserDetails) userDeSer.loadUserByUsername(username);
        
//         if(!matchPassword(password, user.getPassword())) {
//             throw new BadCredentialsException(username);
//         }
 
//         if(!user.isEnabled()) {
//             throw new BadCredentialsException(username);
//         }
        
//         return new UsernamePasswordAuthenticationToken(username, password, user.getAuthorities());
//     }
 
//     @Override
//     public boolean supports(Class<?> authentication) {
//         return true;
//     }
    
//     private boolean matchPassword(String loginPwd, String password) {
//         return loginPwd.equals(password);
//     }
 
// }


