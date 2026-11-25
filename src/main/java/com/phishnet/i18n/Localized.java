package com.phishnet.i18n;

/**
 * Text that can be rendered in any supported language. Passed as a message argument,
 * it is rendered in the same language as the message around it.
 */
@FunctionalInterface
public interface Localized {

    String in(Messages messages);
}
