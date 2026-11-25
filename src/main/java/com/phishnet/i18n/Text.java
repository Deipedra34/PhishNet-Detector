package com.phishnet.i18n;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * A message key and its arguments, kept unrendered so it can be shown in whichever
 * language the reader wants - for example a signal's description, which the CLI
 * prints in the run's language and the REST API in the request's.
 */
public record Text(String key, List<Object> args) implements Localized {

    public Text {
        Objects.requireNonNull(key, "key");
        args = Collections.unmodifiableList(new ArrayList<>(args));
    }

    public static Text of(String key, Object... args) {
        return new Text(key, Arrays.asList(args));
    }

    @Override
    public String in(Messages messages) {
        return messages.get(key, args.toArray());
    }

    /** The English text (the default language). */
    public String english() {
        return in(Messages.english());
    }
}
