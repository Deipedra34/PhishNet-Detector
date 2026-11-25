package com.phishnet.api;

import com.phishnet.i18n.Messages;
import com.phishnet.i18n.Text;
import io.javalin.http.HttpResponseException;
import io.javalin.http.HttpStatus;

/**
 * An error response whose message is shown in the request's language. Its
 * {@link #getMessage()} is the English text.
 */
final class ApiException extends HttpResponseException {

    private final transient Text text;

    ApiException(HttpStatus status, Text text) {
        super(status.getCode(), text.english());
        this.text = text;
    }

    static ApiException badRequest(String key, Object... args) {
        return new ApiException(HttpStatus.BAD_REQUEST, Text.of(key, args));
    }

    String message(Messages messages) {
        return text.in(messages);
    }
}
