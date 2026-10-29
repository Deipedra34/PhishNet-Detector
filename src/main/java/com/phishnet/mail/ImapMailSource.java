package com.phishnet.mail;

import jakarta.mail.FetchProfile;
import jakarta.mail.Flags;
import jakarta.mail.Folder;
import jakarta.mail.FolderClosedException;
import jakarta.mail.FolderNotFoundException;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.UIDFolder;
import org.eclipse.angus.mail.imap.IMAPFolder;
import org.eclipse.angus.mail.imap.IMAPStore;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Watches one IMAP folder with Jakarta Mail (Angus Mail's IMAP provider).
 *
 * <ul>
 *   <li><b>New mail</b> is found by UID: everything above the highest UID seen so far.
 *       The first connection only records that position, so mail that was already in
 *       the folder isn't scanned. After a reconnect the position is kept, so mail that
 *       arrived in between is still scanned - unless the folder's UIDVALIDITY changed
 *       (the server renumbered it), which starts over from the current end.</li>
 *   <li><b>Waiting</b> uses IDLE when the server advertises it, re-issued every
 *       {@link #IDLE_REFRESH} so neither the server nor a NAT box drops the quiet
 *       connection; otherwise it polls with a NOOP every poll interval.</li>
 *   <li><b>Read-only by default</b>: the folder is opened read-only unless flagging or
 *       moving is enabled, and messages are always read with BODY.PEEK, so \Seen is
 *       never changed.</li>
 * </ul>
 */
public final class ImapMailSource implements MailSource {

    /** How long one IDLE lasts before it is refreshed (servers drop IDLE after ~30 minutes). */
    static final Duration IDLE_REFRESH = Duration.ofMinutes(5);

    /** IANA-registered IMAP keyword for phishing, set alongside \Flagged where the server allows keywords. */
    static final String PHISHING_KEYWORD = "$Phishing";

    private final MailServerSettings settings;
    private final boolean readWrite;
    private final String moveFolder;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "phishnet-imap-idle-refresh");
        thread.setDaemon(true);
        return thread;
    });

    private volatile IMAPStore store;
    private volatile IMAPFolder folder;
    private long uidValidity = -1;
    private long lastUid = -1;
    private boolean idleSupported;
    private boolean keywordsAllowed;
    private String notice;

    /**
     * @param actions decides whether the folder is opened read-write, and which folder
     *                (if any) suspicious mail is moved to - created on connect if missing
     */
    public ImapMailSource(MailServerSettings settings, MonitorActions actions) {
        if (settings.protocol() != MailProtocol.IMAP) {
            throw new IllegalArgumentException("not an IMAP server: " + settings.protocol());
        }
        this.settings = settings;
        this.readWrite = actions.mutatesMailbox();
        this.moveFolder = actions.moveToFolder();
    }

    @Override
    public void connect() throws MessagingException {
        close();
        Session session = Session.getInstance(settings.sessionProperties());
        IMAPStore newStore = (IMAPStore) session.getStore(settings.storeProtocol());
        newStore.connect(settings.host(), settings.port(), settings.username(), settings.password());
        try {
            IMAPFolder newFolder = (IMAPFolder) newStore.getFolder(settings.folder());
            if (!newFolder.exists()) {
                throw new FolderNotFoundException(newFolder,
                        "Folder \"" + settings.folder() + "\" doesn't exist on " + settings.host());
            }
            if (moveFolder != null) {
                ensureFolder(newStore, moveFolder);
            }
            newFolder.open(readWrite ? Folder.READ_WRITE : Folder.READ_ONLY);

            idleSupported = newStore.hasCapability("IDLE");
            keywordsAllowed = newFolder.getPermanentFlags() != null
                    && newFolder.getPermanentFlags().contains(Flags.Flag.USER);
            long validity = newFolder.getUIDValidity();
            if (lastUid < 0) {
                lastUid = highestUid(newFolder);
            } else if (validity != uidValidity) {
                lastUid = highestUid(newFolder);
                notice = "The server reset message numbering for " + settings.folder()
                        + " (UIDVALIDITY changed); only mail arriving from now on will be scanned.";
            }
            uidValidity = validity;
            store = newStore;
            folder = newFolder;
        } catch (MessagingException | RuntimeException e) {
            closeQuietly(newStore);
            throw e;
        }
    }

    private static long highestUid(IMAPFolder folder) throws MessagingException {
        long next = folder.getUIDNext();
        if (next > 0) {
            return next - 1;
        }
        int count = folder.getMessageCount();
        return count == 0 ? 0 : folder.getUID(folder.getMessage(count));
    }

    private static IMAPFolder ensureFolder(IMAPStore store, String name) throws MessagingException {
        IMAPFolder target = (IMAPFolder) store.getFolder(name);
        if (!target.exists() && !target.create(Folder.HOLDS_MESSAGES)) {
            throw new FolderNotFoundException(target, "Couldn't create folder \"" + name + "\" on the server");
        }
        return target;
    }

    @Override
    public List<IncomingMail> fetchNew() throws MessagingException {
        IMAPFolder open = requireOpen();
        // "UID n:*" always includes the newest message, even when its UID is below n.
        Message[] candidates = open.getMessagesByUID(lastUid + 1, UIDFolder.LASTUID);
        FetchProfile profile = new FetchProfile();
        profile.add(UIDFolder.FetchProfileItem.UID);
        open.fetch(candidates, profile);

        List<IncomingMail> fresh = new ArrayList<>();
        for (Message message : candidates) {
            if (message == null || message.isExpunged()) {
                continue;
            }
            long uid = open.getUID(message);
            if (uid > lastUid) {
                fresh.add(new IncomingMail(Long.toString(uid), label(uid), message));
            }
        }
        fresh.sort(Comparator.comparingLong(mail -> Long.parseLong(mail.id())));
        return fresh;
    }

    private String label(long uid) {
        return "imap://" + settings.host() + "/" + settings.folder() + ";UID=" + uid;
    }

    @Override
    public void acknowledge(IncomingMail mail) {
        lastUid = Math.max(lastUid, Long.parseLong(mail.id()));
    }

    @Override
    public void awaitNewMail(Duration pollInterval) throws MessagingException, InterruptedException {
        IMAPFolder open = requireOpen();
        if (idleSupported) {
            ScheduledFuture<?> refresh = scheduler.schedule(this::abortIdle,
                    IDLE_REFRESH.toMillis(), TimeUnit.MILLISECONDS);
            try {
                // Returns as soon as the server reports anything (new mail, a flag change,
                // ...) or abortIdle() ends it; fetchNew() then checks what's actually new.
                open.idle(true);
            } finally {
                refresh.cancel(false);
            }
            if (Thread.interrupted()) {
                throw new InterruptedException();
            }
        } else {
            Thread.sleep(pollInterval.toMillis());
            // Gives the server a chance to report new messages (EXISTS) before fetchNew().
            noop(open);
        }
    }

    /** Ends a running IDLE: any command on the folder from another thread makes Angus Mail send DONE first. */
    private void abortIdle() {
        IMAPFolder open = folder;
        if (open != null && open.isOpen()) {
            try {
                noop(open);
            } catch (MessagingException | RuntimeException ignored) {
                // The monitor thread finds out about a broken connection itself.
            }
        }
    }

    private static void noop(IMAPFolder folder) throws MessagingException {
        folder.doCommand(protocol -> {
            protocol.simpleCommand("NOOP", null);
            return null;
        });
    }

    @Override
    public boolean supportsIdle() {
        return idleSupported;
    }

    @Override
    public void flagSuspicious(IncomingMail mail) throws MessagingException {
        Message message = mail.message();
        message.setFlag(Flags.Flag.FLAGGED, true);
        if (keywordsAllowed) {
            message.setFlags(new Flags(PHISHING_KEYWORD), true);
        }
    }

    @Override
    public MoveOutcome move(IncomingMail mail, String folderName) throws MessagingException {
        IMAPFolder open = requireOpen();
        IMAPStore connected = store;
        IMAPFolder target = ensureFolder(connected, folderName);
        Message[] messages = {mail.message()};
        if (connected.hasCapability("MOVE")) {
            open.moveMessages(messages, target);
            return MoveOutcome.MOVED;
        }
        open.copyMessages(messages, target);
        if (connected.hasCapability("UIDPLUS")) {
            // UID EXPUNGE removes only this message, unlike a plain EXPUNGE.
            mail.message().setFlag(Flags.Flag.DELETED, true);
            open.expunge(messages);
            return MoveOutcome.COPIED_AND_DELETED;
        }
        return MoveOutcome.COPIED_ONLY;
    }

    @Override
    public void wakeUp() {
        // Off the calling thread: a shutdown hook shouldn't wait on the network.
        try {
            scheduler.execute(this::abortIdle);
        } catch (RuntimeException ignored) {
            // scheduler already shut down
        }
    }

    @Override
    public void close() {
        IMAPFolder openFolder = folder;
        IMAPStore openStore = store;
        folder = null;
        store = null;
        if (openFolder != null && openFolder.isOpen()) {
            try {
                openFolder.close(false);
            } catch (MessagingException | RuntimeException ignored) {
                // connection may already be gone
            }
        }
        closeQuietly(openStore);
    }

    private static void closeQuietly(IMAPStore store) {
        if (store != null) {
            try {
                store.close();
            } catch (MessagingException | RuntimeException ignored) {
                // connection may already be gone
            }
        }
    }

    @Override
    public String describe() {
        return settings.folder() + " on " + settings.describe();
    }

    @Override
    public String takeNotice() {
        String current = notice;
        notice = null;
        return current;
    }

    private IMAPFolder requireOpen() throws MessagingException {
        IMAPFolder open = folder;
        if (open == null || !open.isOpen()) {
            throw new FolderClosedException(open, "not connected");
        }
        return open;
    }
}
