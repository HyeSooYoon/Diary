package com.diary.em.RestController;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;

import java.util.logging.Logger;

@RestController
@RequestMapping("/api")
public class LoginController {
    
    final private static Logger LOG = Logger.getGlobal();
    public static final String SECURED_TEXT = "Hello from the secured resource!";

    @GetMapping("/test")
    public void test() {
        
        LOG.info("GET successfully called on /login resource");
    }
 
}

