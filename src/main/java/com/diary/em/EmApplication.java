package com.diary.em;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
public class EmApplication {

	public static void main(String[] args) {
		SpringApplication.run(EmApplication.class, args);
	}

}
