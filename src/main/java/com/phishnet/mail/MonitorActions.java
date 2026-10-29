package com.phishnet.mail;

import com.phishnet.model.RiskLevel;

import java.util.Objects;

/**
 * What the monitor does with a scanned message, by risk level. Read-only is the
 * default: flagging and moving only happen when explicitly enabled.
 *
 * @param minLevel       the lowest risk level that counts as suspicious (MEDIUM or HIGH)
 * @param flagSuspicious add \Flagged / $Phishing to suspicious messages ({@code --flag-suspicious})
 * @param moveToFolder   folder to move suspicious messages to, or null ({@code --move-to-folder})
 * @param recordAll      record every scanned message in the history, not only suspicious ones
 */
public record MonitorActions(RiskLevel minLevel, boolean flagSuspicious, String moveToFolder, boolean recordAll) {

    /** Decided actions for one message. */
    public record Plan(boolean suspicious, boolean record, boolean flag, String moveTo) {
        public boolean mutatesMailbox() {
            return flag || moveTo != null;
        }
    }

    public MonitorActions {
        Objects.requireNonNull(minLevel, "minLevel");
        if (minLevel == RiskLevel.LOW) {
            throw new IllegalArgumentException("minLevel must be MEDIUM or HIGH - LOW would treat every message as suspicious");
        }
        if (moveToFolder != null && moveToFolder.isBlank()) {
            throw new IllegalArgumentException("moveToFolder must not be blank");
        }
    }

    /** Log and record MEDIUM and HIGH messages; never touch the mailbox. */
    public static MonitorActions readOnly() {
        return new MonitorActions(RiskLevel.MEDIUM, false, null, false);
    }

    /** True if any action changes the mailbox, which needs the folder opened read-write. */
    public boolean mutatesMailbox() {
        return flagSuspicious || moveToFolder != null;
    }

    public Plan decide(RiskLevel level) {
        boolean suspicious = level.compareTo(minLevel) >= 0;
        return new Plan(suspicious, suspicious || recordAll, suspicious && flagSuspicious,
                suspicious ? moveToFolder : null);
    }
}
