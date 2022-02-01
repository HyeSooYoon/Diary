package com.diary.em.ResponseHandler;

public class CustomAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint{
 
    public CustomAuthenticationEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
    }
 
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        log.debug("CustomAuthenticationEntryPoint.commence ::::");
        super.commence(request, response, authException);
    }
    
}