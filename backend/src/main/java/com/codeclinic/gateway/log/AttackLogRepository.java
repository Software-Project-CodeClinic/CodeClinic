package com.codeclinic.gateway.log;

import org.springframework.data.repository.CrudRepository;

import java.util.UUID;

public interface AttackLogRepository extends CrudRepository<AttackLog, UUID> {}
