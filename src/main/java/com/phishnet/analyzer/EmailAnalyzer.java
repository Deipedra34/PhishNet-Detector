package com.phishnet.analyzer;

import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import com.phishnet.model.UrlAnalysisResult;
import jakarta.mail.Address;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses a .eml message with Jakarta Mail and looks for urgency/threat
 * language (English + Turkish), a display name that doesn't match the real
 * sender address, and any risky links embedded in the body (each one gets
 * run through UrlAnalyzer).
 *
 * Just takes a raw InputStream, so tests can hand it an in-memory .eml
 * fixture instead of touching disk.
 */
public final class EmailAnalyzer {

    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[^\\s\"'<>()\\[\\]]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern HREF_PATTERN = Pattern.compile(
            "href\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern TAG_PATTERN = Pattern.compile("<[^>]+>");

    private final PhishNetConfig config;
    private final UrlAnalyzer urlAnalyzer;

    public EmailAnalyzer(PhishNetConfig config, UrlAnalyzer urlAnalyzer) {
        this.config = config;
        this.urlAnalyzer = urlAnalyzer;
    }

    /**
     * Parses and analyzes a .eml message. Doesn't close the stream. Missing
     * headers, an empty stream, or garbage that isn't valid MIME all degrade
     * to empty values instead of throwing (garbage gets a "malformedEmail"
     * signal too).
     */
    public EmailAnalysisResult analyze(InputStream emlStream) {
        MimeMessage message;
        try {
            message = parseMessage(emlStream);
        } catch (IllegalArgumentException e) {
            Signal malformed = new Signal("malformedEmail", SignalCategory.EMAIL,
                    "Message could not be parsed as a valid email", e.getMessage());
            return new EmailAnalysisResult("", "", "", "", List.of(), List.of(malformed));
        }

        String displayName = "";
        String senderAddress = "";
        InternetAddress from = firstFromAddress(message);
        if (from != null) {
            displayName = from.getPersonal() == null ? "" : from.getPersonal();
            senderAddress = from.getAddress() == null ? "" : from.getAddress();
        }
        String replyToAddress = firstReplyToAddress(message);
        String subject = safeSubject(message);
        String bodyText = extractBodyText(message);

        List<Signal> signals = new ArrayList<>();
        signals.addAll(detectUrgencyLanguage(subject, bodyText));
        signals.addAll(detectSenderMismatch(displayName, senderAddress, replyToAddress));

        List<UrlAnalysisResult> linkResults = new ArrayList<>();
        for (String link : extractLinks(bodyText)) {
            UrlAnalysisResult result = urlAnalyzer.analyze(link);
            linkResults.add(result);
            if (!result.signals().isEmpty()) {
                signals.add(new Signal("riskyEmbeddedLink", SignalCategory.EMAIL,
                        "Embedded link triggered its own risk signals", link));
            }
        }

        return new EmailAnalysisResult(displayName, senderAddress, replyToAddress, subject, linkResults, signals);
    }

    // --- parsing -------------------------------------------------------------

    private static MimeMessage parseMessage(InputStream emlStream) {
        try {
            Session session = Session.getDefaultInstance(new Properties());
            return new MimeMessage(session, emlStream);
        } catch (MessagingException e) {
            throw new IllegalArgumentException("Could not parse .eml message: " + e.getMessage(), e);
        }
    }

    private static InternetAddress firstFromAddress(MimeMessage message) {
        try {
            Address[] from = message.getFrom();
            if (from != null && from.length > 0 && from[0] instanceof InternetAddress) {
                return (InternetAddress) from[0];
            }
        } catch (MessagingException ignored) {
            // no From header present - treated as empty sender
        }
        return null;
    }

    private static String firstReplyToAddress(MimeMessage message) {
        try {
            Address[] replyTo = message.getReplyTo();
            if (replyTo != null && replyTo.length > 0 && replyTo[0] instanceof InternetAddress) {
                String address = ((InternetAddress) replyTo[0]).getAddress();
                return address == null ? "" : address;
            }
        } catch (MessagingException ignored) {
            // no Reply-To header present
        }
        return "";
    }

    private static String safeSubject(MimeMessage message) {
        try {
            String subject = message.getSubject();
            return subject == null ? "" : subject;
        } catch (MessagingException e) {
            return "";
        }
    }

    private static String extractBodyText(MimeMessage message) {
        try {
            Object content = message.getContent();
            StringBuilder sb = new StringBuilder();
            appendContent(content, sb);
            return sb.toString();
        } catch (MessagingException | IOException e) {
            return "";
        }
    }

    private static void appendContent(Object content, StringBuilder sb) throws MessagingException, IOException {
        if (content instanceof String) {
            sb.append((String) content).append('\n');
        } else if (content instanceof Multipart) {
            Multipart multipart = (Multipart) content;
            for (int i = 0; i < multipart.getCount(); i++) {
                Part part = multipart.getBodyPart(i);
                if (part.getContent() != null) {
                    appendContent(part.getContent(), sb);
                }
            }
        } else if (content instanceof InputStream) {
            // Unrecognized binary part (e.g. an attachment with no charset) - skip.
        }
    }

    // --- detectors ---------------------------------------------------------

    private List<Signal> detectUrgencyLanguage(String subject, String body) {
        String haystack = (subject + " " + stripHtmlTags(body)).toLowerCase(Locale.ROOT);
        for (var entry : config.urgencyKeywords().entrySet()) {
            for (String phrase : entry.getValue()) {
                if (haystack.contains(phrase.toLowerCase(Locale.ROOT))) {
                    return List.of(new Signal("urgencyLanguage", SignalCategory.EMAIL,
                            "Message uses urgency/threat language typical of phishing",
                            "[" + entry.getKey() + "] " + phrase));
                }
            }
        }
        return List.of();
    }

    private List<Signal> detectSenderMismatch(String displayName, String senderAddress, String replyToAddress) {
        if (displayName.isEmpty() || senderAddress.isEmpty()) {
            return List.of();
        }
        List<Signal> signals = new ArrayList<>();

        String senderDomain = domainOf(senderAddress);
        String lowerDisplayName = displayName.toLowerCase(Locale.ROOT);
        for (String brand : config.brands()) {
            String normalizedBrand = brand.toLowerCase(Locale.ROOT);
            if (lowerDisplayName.contains(normalizedBrand) && !senderDomain.contains(normalizedBrand)) {
                signals.add(new Signal("senderMismatch", SignalCategory.EMAIL,
                        "Display name references brand '" + brand + "' but sender address domain does not match",
                        displayName + " <" + senderAddress + ">"));
                break;
            }
        }

        if (!replyToAddress.isEmpty() && !replyToAddress.equalsIgnoreCase(senderAddress)
                && !domainOf(replyToAddress).equals(senderDomain)) {
            signals.add(new Signal("senderMismatch", SignalCategory.EMAIL,
                    "Reply-To address domain differs from the sender address domain",
                    senderAddress + " -> " + replyToAddress));
        }

        return signals;
    }

    private static String domainOf(String emailAddress) {
        int at = emailAddress.lastIndexOf('@');
        return at >= 0 ? emailAddress.substring(at + 1).toLowerCase(Locale.ROOT) : "";
    }

    private static String stripHtmlTags(String html) {
        return TAG_PATTERN.matcher(html).replaceAll(" ");
    }

    private static Set<String> extractLinks(String body) {
        Set<String> links = new LinkedHashSet<>();
        Matcher hrefMatcher = HREF_PATTERN.matcher(body);
        while (hrefMatcher.find()) {
            links.add(hrefMatcher.group(1));
        }
        Matcher urlMatcher = URL_PATTERN.matcher(body);
        while (urlMatcher.find()) {
            links.add(urlMatcher.group());
        }
        return links;
    }
}
