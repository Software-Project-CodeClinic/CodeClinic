package com.codeclinic.gateway.feedback;

import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.UUID;

public interface RecommendationRepository extends CrudRepository<Recommendation, Long> {

    List<Recommendation> findByAttackLogId(UUID attackLogId);
}
