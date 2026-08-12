package net.hugmesh.userbff.notification;

import org.springframework.lang.Nullable;

public record SseNotificationEvent(
        String id,
        String category,
        String title,
        @Nullable String body
) {}
