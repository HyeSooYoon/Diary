package com.diary.em.ResponseHandler;

public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler implements ExceptionProcessor {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        log.debug("CustomAuthenticationSuccessHandler.onAuthenticationSuccess ::::");
        /* * 쿠키에 인증 토큰을 넣어준다. */ 
        super.onAuthenticationSuccess(request, response, authentication);
    }

    @Override
    public void makeExceptionResponse(HttpServletRequest request, HttpServletResponse response, Exception exception) {
    }




}
