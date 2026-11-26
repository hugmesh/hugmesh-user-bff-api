package net.hugmesh.userbff.directory;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A small sliding-window limit per signed-in subject for the member directory, so the typeahead answers
 * "who is named like this" at typing speed but cannot be driven to walk the whole directory. A
 * typeahead sends roughly one request per keystroke, hence a window measured in seconds.
 */
@Component
public class DirectoryRateLimiter {

    static final int MAX_REQUESTS = 30;
    static final long WINDOW_MILLIS = 10_000;
    static final int MAX_TRACKED = 10_000;

    private final Clock clock;
    private final ConcurrentHashMap<String, Deque<Long>> hits = new ConcurrentHashMap<>();

    public DirectoryRateLimiter() {
        this(Clock.systemUTC());
    }

    DirectoryRateLimiter(Clock clock) {
        this.clock = clock;
    }

    /** @return true when this subject may make a request now (and records it). */
    public boolean tryAcquire(String subject) {
        long now = clock.millis();
        if (hits.size() > MAX_TRACKED) {
            hits.entrySet().removeIf(e -> e.getValue().isEmpty() || now - e.getValue().peekLast() > WINDOW_MILLIS);
        }
        Deque<Long> q = hits.computeIfAbsent(subject == null ? "" : subject, k -> new ArrayDeque<>());
        synchronized (q) {
            while (!q.isEmpty() && now - q.peekFirst() > WINDOW_MILLIS) {
                q.pollFirst();
            }
            if (q.size() >= MAX_REQUESTS) {
                return false;
            }
            q.addLast(now);
            return true;
        }
    }
}
