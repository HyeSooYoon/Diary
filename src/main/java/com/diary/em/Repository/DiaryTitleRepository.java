package com.diary.em.Repository;

import java.util.List;
import java.util.Optional;
import com.diary.em.Entity.TbDiaryTitle;
import org.springframework.data.jpa.repository.JpaRepository; 
import org.springframework.stereotype.Repository;

@Repository
public interface DiaryTitleRepository extends JpaRepository<TbDiaryTitle, Long> {
    
    Optional<TbDiaryTitle> findTbDiaryTitleByUuid(String uuid);

    List<TbDiaryTitle> findTbDiaryTitleByEmotionCd(String emotion_cd);

    
}
