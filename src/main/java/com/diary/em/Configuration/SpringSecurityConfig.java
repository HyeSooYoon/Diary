package com.diary.em.Configuration;


import com.diary.em.ResponseHandler.CustomAccessDeniedHandler;
import com.diary.em.ResponseHandler.CustomAuthenticationEntryPoint;
import com.diary.em.ResponseHandler.CustomAuthenticationFailureHandler;
import com.diary.em.ResponseHandler.CustomAuthenticationSuccessHandler;
import com.diary.em.ResponseHandler.CustomLogoutSuccessHandler;
import com.diary.em.ResponseHandler.JwtAuthenticationFilter;
import com.diary.em.ResponseHandler.JwtAuthorizationFilter;
import com.diary.em.Util.JwtUtil;
import javax.servlet.*;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${jwt.secret}")//깃허브등에 올릴때 외부에 들어나지 않도록 properties.yml에서 가져옴
    private String secret;

    // private AuthenticationProvider authenticationProvider;

    // public SpringSecurityConfig(AuthenticationProvider authenticationProvider) {
    //     this.authenticationProvider = authenticationProvider;
    // }

    // /* * 스프링 시큐리티가 사용자를 인증하는 방법이 담긴 객체. */ 
    // @Override 
    // protected void configure(AuthenticationManagerBuilder auth) throws Exception { 
    //     auth.authenticationProvider(authenticationProvider); 
    // }

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

    @Override
     protected void configure(AuthenticationManagerBuilder auth) throws Exception {
         auth.inMemoryAuthentication()
             .withUser("foo").password("{noop}bar").roles("USER");
     }
 
    @Override 
    protected void configure(HttpSecurity http) throws Exception { 
        
        //BasicAuthenticationFilter을 상속받음
        Filter filter = new JwtAuthorizationFilter(authenticationManager(),jwtUtil());

        http.formLogin().disable()  //디폴트 로그인 폼을 없앰
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
            .authorizeRequests()                   
            // .antMatchers("/api/**").permitAll()              
            .requestMatchers(CorsUtils::isPreFlightRequest).permitAll() // CORS preflight 일경우 무시
            .anyRequest().authenticated()            
        .and().logout() 
            .logoutUrl("/logout") 
            .logoutSuccessHandler(logoutSuccessHandler()) 
        .and().csrf().disable()      
              .cors().disable() //cors기능을 끔               
              .headers().frameOptions().disable()//iframe 차단기능을 끔
        .and()
            // .addFilter(jwtAuthenticationFilter())//Form Login에 사용되는 custom AuthenticationFilter 구현체를 등록  
            .addFilter(filter)//필터만들어서 적용
        .exceptionHandling() 
            .accessDeniedHandler(accessDeniedHandler()) 
            .authenticationEntryPoint(authenticationEntryPoint()); 
    }
    
    // 프론트 프록시서버 CORS preflight 예외 처리
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();  
        configuration.addAllowedOrigin("http://localhost:8080");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
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
 
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint("/loginPage?error=e");
    }

    /* * Form Login시 걸리는 Filter bean register */ 
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager());
        jwtAuthenticationFilter.setFilterProcessesUrl("/login");
        jwtAuthenticationFilter.setUsernameParameter("username");
        jwtAuthenticationFilter.setPasswordParameter("password");
        jwtAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        jwtAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        jwtAuthenticationFilter.afterPropertiesSet();
        return jwtAuthenticationFilter;
    }
 
    // 간단하게 비밀번호 암호화 
    @Bean 
    public PasswordEncoder passwordEncoder() {        
        return new BCryptPasswordEncoder(); 
    }

    // JwtUtil 빈 등록
    @Bean
    public JwtUtil jwtUtil(){
        return new JwtUtil(secret);
    }


    
}
