package com.diary.em.Configuration;

import com.diary.em.ResponseHandler.CustomAccessDeniedHandler;
import com.diary.em.ResponseHandler.CustomAuthenticationEntryPoint;
import com.diary.em.ResponseHandler.CustomAuthenticationFailureHandler;
import com.diary.em.ResponseHandler.CustomAuthenticationSuccessHandler;
import com.diary.em.ResponseHandler.CustomLogoutSuccessHandler;
import com.diary.em.ResponseHandler.JwtAuthenticationFilter;
import com.diary.em.ResponseHandler.JwtAuthorizationFilter;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    // private AuthenticationProvider authenticationProvider;

    // public SpringSecurityConfig(AuthenticationProvider authenticationProvider) {
    //     this.authenticationProvider = authenticationProvider;
    // }

    // /* * ????????? ??????????????? ???????????? ???????????? ????????? ?????? ??????. */ 
    // @Override 
    // protected void configure(AuthenticationManagerBuilder auth) throws Exception { 
    //     auth.authenticationProvider(authenticationProvider); 
    // }

    /* * ????????? ???????????? ?????? ???????????? ?????? Url ??????(?????? ???????????? ?????? ???????????? ??????) */ 
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
        // .antMatchers("/resources/**")
        // .antMatchers("/css/**")
        // .antMatchers("/vendor/**")
        // .antMatchers("/js/**")
        // .antMatchers("/favicon*/**")
        .antMatchers("/**");
    }

    /* * ????????? ???????????? ?????? */         
    @Override 
    protected void configure(HttpSecurity http) throws Exception { 
        http.authorizeRequests()                   //????????? ????????? URI??? ????????? ??? ?????? ????????? ?????? 
            .antMatchers("/login*/**").permitAll() //?????? ?????? ?????? 
            .antMatchers("/logout/**").permitAll() 
            .antMatchers("/myPage").hasRole("ADMIN")//admin????????? ?????? ?????? ???????????? ?????? ?????? 
            .antMatchers("/chatbot/**").permitAll() 
            .anyRequest().authenticated() 
        .and().logout() 
            .logoutUrl("/logout") 
            .logoutSuccessHandler(logoutSuccessHandler()) 
        .and().csrf()                        
              .disable()                     //?????? ????????? ???????????? ???????????? ?????????????????? csrf????????? ??????????????? 
        .addFilter(jwtAuthenticationFilter())//Form Login??? ???????????? custom AuthenticationFilter ???????????? ?????? 
        .addFilter(jwtAuthorizationFilter()) //Header ????????? ???????????? BasicAuthenticationFilter ???????????? ?????? 
        .exceptionHandling() 
            .accessDeniedHandler(accessDeniedHandler()) 
            .authenticationEntryPoint(authenticationEntryPoint()) ; 
    } 
    
    /* * SuccessHandler bean register */     
    @Bean 
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        CustomAuthenticationSuccessHandler successHandler = new CustomAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/index");
        return successHandler;
    }

    /* * FailureHandler bean register */ 
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        CustomAuthenticationFailureHandler failureHandler = new CustomAuthenticationFailureHandler();
        failureHandler.setDefaultFailureUrl("/loginPage?error=error");
        return failureHandler;
    }

    /* * LogoutSuccessHandler bean register */ 
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        CustomLogoutSuccessHandler logoutSuccessHandler = new CustomLogoutSuccessHandler();
        logoutSuccessHandler.setDefaultTargetUrl("/loginPage?logout=logout");
        return logoutSuccessHandler;
    }

    /* * AccessDeniedHandler bean register */ 
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/error/403");
        return accessDeniedHandler;
    }

    /* * AuthenticationEntryPoint bean register */ 
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint("/loginPage?error=e");
    }

    /* * Form Login??? ????????? Filter bean register */ 
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

    /* * Filter bean register */ 
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() throws Exception {
        JwtAuthorizationFilter jwtAuthorizationFilter = new JwtAuthorizationFilter(authenticationManager());
        return jwtAuthorizationFilter;
    }

    @Bean 
    public PasswordEncoder passwordEncoder() {
        //???????????? ???????????? ????????? 
        return new BCryptPasswordEncoder(); 
    }


    
}
