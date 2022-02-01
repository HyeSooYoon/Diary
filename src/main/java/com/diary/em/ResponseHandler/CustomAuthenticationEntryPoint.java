package com.diary.em.ResponseHandler;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint{
 
    public CustomAuthenticationEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
    }
 
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.debug("CustomAuthenticationEntryPoint.commence ::::");
        super.commence(request, response, authException);
    }
    
}