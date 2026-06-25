package systems.snapdragon.userbff.notification;

import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-user Reactor {@link Sinks.Many} registry for the in-app SSE push path.
 *
 * <p>A sink is created on first {@link #subscribe} and removed on stream termination or
 * cancel, so {@link #publish} is a guaranteed no-op for users without an open connection —
 * no memory leak even when the browser tab is closed.
 */
@Component
public class SseNotificationBus {

    private final ConcurrentHashMap<String, Sinks.Many<SseNotificationEvent>> sinks =
            new ConcurrentHashMap<>();

    /**
     * Returns a multicast {@link Flux} of events for {@code userId}. Creates the sink on
     * first call; removes it from the registry when the subscriber cancels or the stream
     * terminates so {@link #publish} becomes a no-op for disconnected users.
     */
    public Flux<SseNotificationEvent> subscribe(String userId) {
        Sinks.Many<SseNotificationEvent> sink = sinks.computeIfAbsent(userId,
                id -> Sinks.many().multicast().onBackpressureBuffer(16, false));
        // remove sink on stream termination so publish becomes a no-op for disconnected users
        return sink.asFlux().doFinally(signal -> sinks.remove(userId, sink));
    }

    /**
     * Pushes {@code event} to the open stream for {@code userId}. No-op when the user has
     * no active subscriber (avoids accumulating events for offline users).
     */
    public void publish(String userId, SseNotificationEvent event) {
        Sinks.Many<SseNotificationEvent> sink = sinks.get(userId);
        if (sink != null) {
            sink.tryEmitNext(event);
        }
    }
}
