package com.diary.em.RestController;

import javax.validation.Valid; 
import com.diary.em.Dto.DiaryContents;
import com.diary.em.Service.EmDiarySaveService; 
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired; 
import org.springframework.validation.FieldError;  
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class DiaryController { 
    
    @Autowired
    private final EmDiarySaveService emDiarySaveService; 
    StringBuilder stringBuilder;

    @GetMapping("/test")
    public String test() {
        return "하이";
    }

    @PostMapping("/add")
    public DiaryContents DiaryContentsSave(@RequestBody @Valid DiaryContents req, BindingResult bindingResult) { 
        
        if (bindingResult.hasErrors()) {            
            stringBuilder = new StringBuilder();

            for (FieldError fieldError : bindingResult.getFieldErrors()) { 
                stringBuilder.append(fieldError.getField() + " " + fieldError.getDefaultMessage()); 
            }

            throw new RuntimeException(stringBuilder.toString());
        } 
        
        return emDiarySaveService.createDiary(req);
    }

}
