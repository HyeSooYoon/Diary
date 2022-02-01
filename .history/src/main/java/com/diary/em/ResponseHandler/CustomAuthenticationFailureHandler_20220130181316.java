package com.diary.em.ResponseHandler;

@Slf4j
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler implements ExceptionProcessor {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
        log.debug("CustomAuthenticationFailureHandler.onAuthenticationFailure ::::");
        super.onAuthenticationFailure(request, response, exception);
    }

    @Override
    public void makeExceptionResponse(HttpServletRequest request, HttpServletResponse response, Exception exception) {
    }

    
}
