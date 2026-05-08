package com.codeclinic.gateway.log;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * attack_logs 테이블 JDBC 엔티티.
 * TimescaleDB hypertable — (id, timestamp) 복합 PK.
 */
@Table("attack_logs")
@Getter
@Builder
@AllArgsConstructor
public class AttackLog {

    @Id
    private final UUID    id;

    private final Instant timestamp;

    @Column("source_ip")
    private final String  sourceIp;

    private final String  method;
    private final String  uri;

    @Column("cwe_type")
    private final String  cweType;

    private final double  score;
    private final String  verdict;

    @Column("raw_input")
    private final String  rawInput;
}
