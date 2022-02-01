package com.diary.em.ResponseHandler;

public interface ExceptionProcessor {

    public void makeExceptionResponse(HttpServletRequest request, HttpServletResponse response, Exception exception) throws IOException;
    
}
