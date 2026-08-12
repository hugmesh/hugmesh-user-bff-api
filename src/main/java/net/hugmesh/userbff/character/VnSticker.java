package net.hugmesh.userbff.character;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * One VN-CHARACTER EXPRESSION STICKER belonging to the caller (table
 * {@code vn_sticker_pack}). This is the wire shape returned to the client: the saved
 * {@code id}, the owner, the canonical {@code expression} label, the homeserver media
 * {@code mxcUrl} of the rendered PNG, the moderation {@code status} (PENDING on save),
 * and {@code createdAt}.
 *
 * <p>{@code ownerSubject} is the Casdoor JWT subject and is NEVER accepted from the
 * request body (the controller always sets it from the JWT subject), so a user cannot
 * record/read a sticker under another user. The {@code mxcUrl} is the homeserver
 * media-upload result (a stub {@code mxc://} when the live upload ships dark) — the raw
 * PNG bytes are never returned, only the durable media ref.
 *
 * <p>{@code status} vocabulary (DB-paralleled by the 017 CHECK constraint):
 * {@code PENDING} (just saved + moderated-passed, awaiting human review) |
 * {@code ACTIVE} (a moderator approved it — only ACTIVE rows are later advertised in the
 * MSC2545 pack) | {@code REJECTED} (a moderator blocked it).
 *
 * <p>{@code findingId} (changelog 018, nullable) is the federation {@code @system}
 * finding id this row filed at save time — the back-link the moderation reconciler uses
 * to flip this row's {@code status} when the finding is resolved. {@code null} when the
 * best-effort capture didn't complete (a federation outage at file time).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record VnSticker(
        String id,
        String ownerSubject,
        String domain,
        String expression,
        String mxcUrl,
        String status,
        Long findingId,
        Instant createdAt) {

    /**
     * The sticker's embed/serve SLUG — the DB-generated UUID {@code id}, surfaced under
     * the field name the forum-ui sticker layer keys on (its picker normalizer drops any
     * list item without a {@code slug}, and its token grammar {@code :snap-sticker:<slug>:}
     * + body URL {@code /bff/user/character/stickers/{slug}/body} both validate the
     * charset {@code [a-z0-9_-]{1,64}} — which a lowercase-hex-and-hyphens UUID always
     * fits). Serialized alongside {@code id} (same value) so existing consumers keep
     * their field.
     */
    @JsonProperty("slug")
    public String slug() {
        return id;
    }

    /** Human label for picker/editor grids (forum-ui falls back to the raw slug — a bare
     *  UUID — without one): the canonical expression name ({@code happy}, {@code smug}, …). */
    @JsonProperty("label")
    public String label() {
        return expression;
    }
}
