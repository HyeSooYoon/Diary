package com.diary.em.Configuration;

import com.diary.em.ResponseHandler.CustomAccessDeniedHandler;
import com.diary.em.ResponseHandler.CustomAuthenticationEntryPoint;
import com.diary.em.ResponseHandler.CustomAuthenticationFailureHandler;
import com.diary.em.ResponseHandler.CustomAuthenticationSuccessHandler;
import com.diary.em.ResponseHandler.CustomLogoutSuccessHandler;
import com.diary.em.Util.JwtAuthenticationFilter; 
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;

    // 암호화에 필요한 PasswordEncoder 를 Bean 등록합니다.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // authenticationManager를 Bean 등록합니다.
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override 
    protected void configure(HttpSecurity http) throws Exception {   

        http
        .httpBasic().disable() // rest api 만을 고려하여 기본 설정은 해제하겠습니다.
        .csrf().disable() // csrf 보안 토큰 disable처리.
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 토큰 기반 인증이므로 세션 역시 사용하지 않습니다.
        .and()
            .authorizeRequests() // 요청에 대한 사용권한 체크
            // .antMatchers("/admin/**").hasRole("ADMIN")
            // .anyRequest().permitAll() // 그외 나머지 요청은 누구나 접근 가능
            .antMatchers("/api/auth/**", "/redisTest/**").permitAll()
            .anyRequest().authenticated()   // 나머지 API 는 전부 인증 필요
        .and()
            .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
        // JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 전에 넣는다
            .logout() 
            .logoutUrl("/logout") 
            .logoutSuccessHandler(logoutSuccessHandler()) 
        .and()
        .exceptionHandling() 
            .accessDeniedHandler(accessDeniedHandler()) 
            .authenticationEntryPoint(authenticationEntryPoint()); 
    }
 

    // @Override
    // public void configure(WebSecurity web) throws Exception {
    //     web.ignoring()
    //     // .antMatchers("/resources/**")
    //     // .antMatchers("/css/**")
    //     // .antMatchers("/vendor/**")
    //     // .antMatchers("/js/**")
    //     // .antMatchers("/favicon*/**")
    //     .antMatchers("/**");
    // }

    // @Override
    //  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //      auth.inMemoryAuthentication()
    //          .withUser("foo").password("{noop}bar").roles("USER");
    //  }
 
    
    
    // 프론트 프록시서버 CORS preflight 예외 처리
    // @Bean
    // public CorsConfigurationSource corsConfigurationSource() {
    //     CorsConfiguration configuration = new CorsConfiguration();  
    //     configuration.addAllowedOrigin("http://localhost:8080");
    //     configuration.addAllowedMethod("*");
    //     configuration.addAllowedHeader("*");
    //     configuration.setAllowCredentials(false);
    //     configuration.setMaxAge(3600L);
    //     UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    //     source.registerCorsConfiguration("/**", configuration);
    //     return source;
    // }
    
    // 핸들러 처리
    @Bean 
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        CustomAuthenticationSuccessHandler successHandler = new CustomAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/indexff");
        return successHandler;
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        CustomAuthenticationFailureHandler failureHandler = new CustomAuthenticationFailureHandler();
        failureHandler.setDefaultFailureUrl("/loginPage?error=error");
        return failureHandler;
    }
 
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        CustomLogoutSuccessHandler logoutSuccessHandler = new CustomLogoutSuccessHandler();
        logoutSuccessHandler.setDefaultTargetUrl("/loginPage?logout=logout");
        return logoutSuccessHandler;
    }
 
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/error/403");
        return accessDeniedHandler;
    }
 
    // JWT토큰 권한 없음.. 
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint("/loginPage?error=e");
    } 
 
    
 

    
}
