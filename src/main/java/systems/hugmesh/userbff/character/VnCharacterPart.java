package systems.hugmesh.userbff.character;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * One USER-DRAWN character PART belonging to the caller (table {@code vn_character_part}).
 * This is the wire shape returned to the client: the saved {@code id}, the owner, the
 * label {@code name}, the SERVER-SANITIZED {@code svg}, the moderation {@code status}
 * (PENDING on save), the optional {@code headArchetype}, and {@code createdAt}.
 *
 * <p>{@code ownerSubject} is the Casdoor JWT subject and is NEVER accepted from the
 * request body (the controller always sets it from the JWT subject), so a user cannot
 * record/read a part under another user. The {@code svg} is the sanitized subset
 * ({@link systems.hugmesh.userbff.svg.SvgSanitizerService} runs BEFORE this is
 * persisted) — raw client XML never reaches this record.
 *
 * <p>{@code status} vocabulary (DB-paralleled by the 016 CHECK constraint):
 * {@code PENDING} (just saved, awaiting human moderation of the sanitized SVG) |
 * {@code ACTIVE} (a moderator approved it) | {@code REJECTED} (a moderator blocked it).
 *
 * <p>{@code findingId} (changelog 018, nullable) is the federation {@code @system}
 * finding id this row filed at save time — the back-link the moderation reconciler uses
 * to flip this row's {@code status} when the finding is resolved. {@code null} when the
 * best-effort capture didn't complete (a federation outage at file time).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record VnCharacterPart(
        String id,
        String ownerSubject,
        String domain,
        String name,
        String svg,
        String status,
        String headArchetype,
        Long findingId,
        Instant createdAt) {
}
