package com.phishnet.mail;

import jakarta.mail.FetchProfile;
import jakarta.mail.Folder;
import jakarta.mail.FolderClosedException;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.UIDFolder;
import org.eclipse.angus.mail.pop3.POP3Folder;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Polls a POP3 mailbox (Angus Mail's POP3 provider). POP3 has no IDLE, no flags, and
 * no folders, so this is always read-only polling of INBOX: a POP3 server only shows
 * mail that arrived before the session started, so each poll is a fresh login.
 * New messages are told apart by their UIDL ids; the ones present on the first poll
 * count as already seen. Nothing is ever deleted from the server.
 */
public final class Pop3MailSource implements MailSource {

    private final MailServerSettings settings;
    private final Set<String> seen = new HashSet<>();
    private boolean baselineTaken;

    private volatile Store store;
    private volatile POP3Folder folder;

    public Pop3MailSource(MailServerSettings settings) {
        if (settings.protocol() != MailProtocol.POP3) {
            throw new IllegalArgumentException("not a POP3 server: " + settings.protocol());
        }
        this.settings = settings;
    }

    @Override
    public void connect() throws MessagingException {
        openSession();
        if (!baselineTaken) {
            seen.addAll(currentUids().keySet());
            baselineTaken = true;
        }
    }

    private void openSession() throws MessagingException {
        close();
        Session session = Session.getInstance(settings.sessionProperties());
        Store newStore = session.getStore(settings.storeProtocol());
        newStore.connect(settings.host(), settings.port(), settings.username(), settings.password());
        try {
            POP3Folder inbox = (POP3Folder) newStore.getFolder("INBOX");
            inbox.open(Folder.READ_ONLY);
            store = newStore;
            folder = inbox;
        } catch (MessagingException | RuntimeException e) {
            try {
                newStore.close();
            } catch (MessagingException ignored) {
                // already failing
            }
            throw e;
        }
    }

    /** UIDL id -> message, in mailbox order. */
    private Map<String, Message> currentUids() throws MessagingException {
        POP3Folder open = folder;
        if (open == null || !open.isOpen()) {
            throw new FolderClosedException(open, "not connected");
        }
        Message[] messages = open.getMessages();
        FetchProfile profile = new FetchProfile();
        profile.add(UIDFolder.FetchProfileItem.UID);
        open.fetch(messages, profile);
        Map<String, Message> byUid = new LinkedHashMap<>();
        for (Message message : messages) {
            String uid = open.getUID(message);
            if (uid == null) {
                throw new IllegalArgumentException("The POP3 server doesn't support UIDL, which the monitor needs "
                        + "to tell new messages apart; use IMAP instead");
            }
            byUid.put(uid, message);
        }
        return byUid;
    }

    @Override
    public List<IncomingMail> fetchNew() throws MessagingException {
        if (folder == null) {
            openSession();
        }
        Map<String, Message> current = currentUids();
        // Forget ids of messages deleted from the server, so the set doesn't grow forever.
        seen.retainAll(new LinkedHashSet<>(current.keySet()));
        List<IncomingMail> fresh = new ArrayList<>();
        current.forEach((uid, message) -> {
            if (!seen.contains(uid)) {
                fresh.add(new IncomingMail(uid, "pop3://" + settings.host() + "/INBOX;UIDL=" + uid, message));
            }
        });
        return fresh;
    }

    @Override
    public void acknowledge(IncomingMail mail) {
        seen.add(mail.id());
    }

    @Override
    public void awaitNewMail(Duration pollInterval) throws InterruptedException {
        close();
        Thread.sleep(pollInterval.toMillis());
    }

    @Override
    public boolean supportsIdle() {
        return false;
    }

    @Override
    public void flagSuspicious(IncomingMail mail) throws MessagingException {
        throw new MessagingException("POP3 can't flag messages - use IMAP for --flag-suspicious");
    }

    @Override
    public MoveOutcome move(IncomingMail mail, String folderName) throws MessagingException {
        throw new MessagingException("POP3 has no folders - use IMAP for --move-to-folder");
    }

    @Override
    public void wakeUp() {
        // Nothing blocks on the network between polls; interrupting the monitor thread ends the sleep.
    }

    @Override
    public void close() {
        Folder openFolder = folder;
        Store openStore = store;
        folder = null;
        store = null;
        try {
            if (openFolder != null && openFolder.isOpen()) {
                openFolder.close(false);
            }
        } catch (MessagingException | RuntimeException ignored) {
            // connection may already be gone
        }
        try {
            if (openStore != null) {
                openStore.close();
            }
        } catch (MessagingException | RuntimeException ignored) {
            // connection may already be gone
        }
    }

    @Override
    public String describe() {
        return "INBOX on " + settings.describe();
    }
}
