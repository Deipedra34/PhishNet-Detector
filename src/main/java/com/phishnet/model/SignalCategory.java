package com.phishnet.model;

/**
 * Which analyzer produced a given {@link Signal}. Used for grouping and reporting.
 */
public enum SignalCategory {
    URL,
    SSL,
    EMAIL
}
