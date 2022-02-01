package com.diary.em.RestController;

import org.springframework.web.bind.annotation.GetMapping;

public class HelloController {
    @GetMapping("/api/hello")
    public String hello() {
        return "hello";
    }
    
}
