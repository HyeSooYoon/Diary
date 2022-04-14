package com.diary.em.Repository;

import org.springframework.data.jpa.repository.JpaRepository; 
import org.springframework.stereotype.Repository; 
import java.util.Optional;
import com.diary.em.Entity.TbDiaryContents;

@Repository
public interface DiaryRepository extends JpaRepository<TbDiaryContents, Long> {

    Optional<TbDiaryContents> findTbDiaryContentsByUuid(String uuid);    
}
