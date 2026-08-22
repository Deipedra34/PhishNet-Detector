package com.phishnet.util;

import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.PhishNetConfig.ScoringConfig;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Loads PhishNetConfig from YAML - a file path, a stream, or the bundled
 * default resource. Parses into a plain Map first instead of using
 * SnakeYAML's bean binding, so PhishNetConfig itself can stay immutable
 * with no setters.
 */
public final class ConfigLoader {

    private static final String DEFAULT_RESOURCE = "/phishnet-config.yaml";

    private ConfigLoader() {
    }

    /** Loads the configuration bundled with the jar ({@code phishnet-config.yaml} on the classpath). */
    public static PhishNetConfig loadDefault() {
        try (InputStream in = ConfigLoader.class.getResourceAsStream(DEFAULT_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Bundled default config resource not found: " + DEFAULT_RESOURCE);
            }
            return load(in);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load bundled default config", e);
        }
    }

    /** Loads configuration from a user-supplied YAML file path (e.g. via {@code --config}). */
    public static PhishNetConfig load(Path path) {
        try (InputStream in = Files.newInputStream(path)) {
            return load(in);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read config file: " + path, e);
        }
    }

    /** Loads configuration from an already-open stream. Does not close the stream. */
    @SuppressWarnings("unchecked")
    public static PhishNetConfig load(InputStream in) {
        Yaml yaml = new Yaml();
        Object loaded = yaml.load(in);
        if (!(loaded instanceof Map)) {
            throw new IllegalArgumentException("Config YAML root must be a mapping");
        }
        Map<String, Object> root = (Map<String, Object>) loaded;

        List<String> brands = stringList(root.get("brands"));
        List<String> suspiciousTlds = stringList(root.get("suspiciousTlds"));
        List<String> urlShorteners = stringList(root.get("urlShorteners"));

        Map<String, List<String>> urgencyKeywords = new LinkedHashMap<>();
        Object rawKeywords = root.get("urgencyKeywords");
        if (rawKeywords instanceof Map) {
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) rawKeywords).entrySet()) {
                urgencyKeywords.put(entry.getKey(), stringList(entry.getValue()));
            }
        }

        Object rawScoring = root.get("scoring");
        Map<String, Object> scoringMap = (rawScoring instanceof Map)
                ? (Map<String, Object>) rawScoring
                : Map.of();

        Map<String, Integer> weights = new LinkedHashMap<>();
        Object rawWeights = scoringMap.get("weights");
        if (rawWeights instanceof Map) {
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) rawWeights).entrySet()) {
                weights.put(entry.getKey(), ((Number) entry.getValue()).intValue());
            }
        }

        int mediumThreshold = intValue(scoringMap.get("mediumThreshold"), 30);
        int highThreshold = intValue(scoringMap.get("highThreshold"), 60);
        int typosquattingMaxDistance = intValue(scoringMap.get("typosquattingMaxDistance"), 2);
        int longUrlThreshold = intValue(scoringMap.get("longUrlThreshold"), 75);
        int maxQueryParams = intValue(scoringMap.get("maxQueryParams"), 8);
        int encodedCharThreshold = intValue(scoringMap.get("encodedCharThreshold"), 5);

        ScoringConfig scoring = new ScoringConfig(weights, mediumThreshold, highThreshold,
                typosquattingMaxDistance, longUrlThreshold, maxQueryParams, encodedCharThreshold);

        return new PhishNetConfig(brands, suspiciousTlds, urlShorteners, urgencyKeywords, scoring);
    }

    @SuppressWarnings("unchecked")
    private static List<String> stringList(Object raw) {
        List<String> result = new ArrayList<>();
        if (raw instanceof List) {
            for (Object item : (List<Object>) raw) {
                result.add(String.valueOf(item));
            }
        }
        return result;
    }

    private static int intValue(Object raw, int fallback) {
        return raw instanceof Number ? ((Number) raw).intValue() : fallback;
    }
}
