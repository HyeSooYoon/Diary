package com.diary.em.ResponseHandler;

@Slf4j
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        log.debug("CustomLogoutSuccessHandler.onLogoutSuccess ::::");
        super.onLogoutSuccess(request, response, authentication);
    }

    
}
