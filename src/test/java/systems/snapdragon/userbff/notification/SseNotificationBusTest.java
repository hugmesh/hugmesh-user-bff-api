package systems.snapdragon.userbff.notification;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

class SseNotificationBusTest {

    private final SseNotificationBus bus = new SseNotificationBus();

    @Test
    void subscribe_receivesPublishedEvent() {
        SseNotificationEvent event = new SseNotificationEvent("id1", "role-change", "Role changed", null);

        StepVerifier.create(bus.subscribe("user-1"))
                .expectSubscription()
                .then(() -> bus.publish("user-1", event))
                .expectNext(event)
                .thenCancel()
                .verify();
    }

    @Test
    void publish_isNoopWhenNoSubscriber() {
        SseNotificationEvent event = new SseNotificationEvent("id2", "account-restriction", "Restricted", "details");
        bus.publish("nonexistent-user", event);
        // no exception expected
    }
}
