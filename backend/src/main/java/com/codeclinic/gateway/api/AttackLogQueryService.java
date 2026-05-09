package com.codeclinic.gateway.api;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AttackLogQueryService {

    private final JdbcTemplate jdbc;

    public AttackPageResponse findAll(String cweLabel, String verdict, Instant from, Instant to,
                                      int page, int size) {
        List<Object> params = new ArrayList<>();
        String where = buildWhere(cweLabel, verdict, from, to, params);

        Long total = jdbc.queryForObject("SELECT COUNT(*) FROM attack_logs" + where,
                Long.class, params.toArray());

        params.add(size);
        params.add((long) page * size);
        List<AttackSummary> content = jdbc.query(
                "SELECT id, timestamp, cwe_type, verdict, score, uri FROM attack_logs"
                        + where + " ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (rs, i) -> new AttackSummary(
                        UUID.fromString(rs.getString("id")),
                        rs.getTimestamp("timestamp").toInstant(),
                        rs.getString("cwe_type"),
                        rs.getString("verdict"),
                        rs.getDouble("score"),
                        rs.getString("uri")),
                params.toArray());

        return new AttackPageResponse(content, total != null ? total : 0L, page, size);
    }

    public Optional<AttackDetailResponse> findById(UUID id) {
        List<AttackDetailResponse> rows = jdbc.query(
                "SELECT id, timestamp, cwe_type, verdict, score, uri, raw_input, source_ip"
                        + " FROM attack_logs WHERE id = ?",
                (rs, i) -> new AttackDetailResponse(
                        UUID.fromString(rs.getString("id")),
                        rs.getTimestamp("timestamp").toInstant(),
                        rs.getString("cwe_type"),
                        rs.getString("verdict"),
                        rs.getDouble("score"),
                        rs.getString("uri"),
                        rs.getString("raw_input"),
                        rs.getString("source_ip")),
                id);
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.getFirst());
    }

    public List<RecommendationResponse> findRecommendations(UUID attackLogId) {
        return jdbc.query(
                "SELECT cwe_type, pattern, suggestion, file_path, line_number"
                        + " FROM recommendations WHERE attack_log_id = ?",
                (rs, i) -> new RecommendationResponse(
                        rs.getString("cwe_type"),
                        rs.getString("pattern"),
                        rs.getString("suggestion"),
                        rs.getString("file_path"),
                        rs.getObject("line_number") != null ? rs.getInt("line_number") : null),
                attackLogId);
    }

    public StatsResponse getStats() {
        Long block   = jdbc.queryForObject(
                "SELECT COUNT(*) FROM attack_logs WHERE verdict = 'BLOCK'",   Long.class);
        Long monitor = jdbc.queryForObject(
                "SELECT COUNT(*) FROM attack_logs WHERE verdict = 'MONITOR'", Long.class);

        Map<String, Long> byLabel = jdbc.queryForList(
                        "SELECT cwe_type, COUNT(*) AS cnt FROM attack_logs"
                                + " WHERE cwe_type IS NOT NULL GROUP BY cwe_type")
                .stream()
                .collect(Collectors.toMap(
                        r -> (String) r.get("cwe_type"),
                        r -> ((Number) r.get("cnt")).longValue()));

        return new StatsResponse(
                block   != null ? block   : 0L,
                monitor != null ? monitor : 0L,
                byLabel);
    }

    private String buildWhere(String cweLabel, String verdict, Instant from, Instant to,
                               List<Object> params) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (cweLabel != null) { where.append(" AND cwe_type = ?");   params.add(cweLabel); }
        if (verdict  != null) { where.append(" AND verdict = ?");    params.add(verdict); }
        if (from     != null) { where.append(" AND timestamp >= ?"); params.add(Timestamp.from(from)); }
        if (to       != null) { where.append(" AND timestamp <= ?"); params.add(Timestamp.from(to)); }
        return where.toString();
    }
}
