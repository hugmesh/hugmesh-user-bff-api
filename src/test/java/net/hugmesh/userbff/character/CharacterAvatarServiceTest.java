package net.hugmesh.userbff.character;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.media.ImageSniffer;
import net.hugmesh.userbff.profile.UserProfileRepository;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for {@link CharacterAvatarService} — the ACCESS RULE and the RASTER GATE
 * behind {@code GET /bff/user/character/avatar/{ref}/body}.
 *
 * <p>The rule is the reason this route exists at all: a VN sprite is the POST AUTHOR's
 * avatar rendered in a READER's browser, so an owner-scoped serve (which is what
 * {@code /bff/user/profile/avatar/body} is) cannot do the job. Mirrors
 * {@code StickerService.servesTo}'s ACTIVE branch — owner always, otherwise same brand
 * only — and every refusal is the same EMPTY result the controller turns into one
 * uniform 404.
 */
class CharacterAvatarServiceTest {

    private static final String REF = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    private static final byte[] PNG = {(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10, 1, 2, 3, 4};

    private final UserProfileRepository profiles = mock(UserProfileRepository.class);
    private final CharacterAvatarService service = new CharacterAvatarService(profiles);

    private void storedRow(String owner, String domain, String contentType) {
        when(profiles.findAvatarBodyByRef(REF)).thenReturn(Mono.just(
                new UserProfileRepository.AvatarBodyForRef(PNG, contentType, owner, domain)));
    }

    // ── the caller's own handle ─────────────────────────────

    @Test
    void refForOwner_withStoredPixels_returnsTheStableHandle() {
        when(profiles.findAvatarBody("alice", "default")).thenReturn(Mono.just(
                new UserProfileRepository.AvatarBody(PNG, "image/png")));
        when(profiles.ensureAvatarRef("alice", "default")).thenReturn(Mono.just(REF));

        assertThat(service.refForOwner("alice", "default").block()).isEqualTo(REF);
    }

    @Test
    void refForOwner_noStoredPixels_isEmpty_andMintsNothing() {
        // Gate on the PIXELS: publishing a handle for an empty slot would hand the UI a
        // ref that 404s, which is the broken-image defect all over again.
        when(profiles.findAvatarBody("alice", "default")).thenReturn(Mono.empty());

        assertThat(service.refForOwner("alice", "default").blockOptional()).isEmpty();
        verify(profiles, never()).ensureAvatarRef(anyString(), any());
    }

    // ── the cross-user serve rule ───────────────────────────

    @Test
    void serveBody_owner_getsTheirOwnPixels() {
        storedRow("alice", "default", "image/png");

        CharacterAvatarService.AvatarBody body = service.serveBody(REF, "alice", "default").block();

        assertThat(body).isNotNull();
        assertThat(body.bytes()).isEqualTo(PNG);
        assertThat(body.contentType()).isEqualTo("image/png");
    }

    @Test
    void serveBody_otherUserSameBrand_getsThePixels() {
        // THE POINT OF THE ROUTE: bob reads a thread alice posted in, so alice's sprite
        // must resolve in bob's browser. An owner-scoped serve would hand bob his own
        // avatar on every one of alice's posts.
        storedRow("alice", "default", "image/png");

        assertThat(service.serveBody(REF, "bob", "default").block()).isNotNull();
    }

    @Test
    void serveBody_otherUserOtherBrand_isEmpty() {
        storedRow("alice", "default", "image/png");

        assertThat(service.serveBody(REF, "bob", "other-brand").blockOptional()).isEmpty();
    }

    @Test
    void serveBody_unscopedSuperadminCaller_getsThePixels() {
        storedRow("alice", "default", "image/png");

        assertThat(service.serveBody(REF, "root", null).block()).isNotNull();
    }

    @Test
    void serveBody_unknownHandle_isEmpty() {
        when(profiles.findAvatarBodyByRef(anyString())).thenReturn(Mono.empty());

        assertThat(service.serveBody("00000000-0000-0000-0000-000000000000", "bob", "default")
                .blockOptional()).isEmpty();
    }

    @Test
    void serveBody_missingStoredType_fallsBackToThePngFloor() {
        storedRow("alice", "default", null);

        assertThat(service.serveBody(REF, "alice", "default").block().contentType())
                .isEqualTo("image/png");
    }

    // ── the SVG rule, enforced on the READ side too ─────────

    @Test
    void serveBody_svgStoredType_isNeverServed_noteEvenToItsOwner() {
        // SVG cannot be uploaded (ImageSniffer rejects vectors, so the write path 400s),
        // and these bytes now land in an <img> in OTHER people's browsers — so the read
        // side refuses it as well. A row that somehow carried image/svg+xml (migration,
        // hand edit, a future write path) must serve NOTHING, not cross-user stored XSS.
        for (String vector : List.of("image/svg+xml", "text/html", "application/xml",
                "image/svg+xml; charset=utf-8")) {
            storedRow("alice", "default", vector);
            assertThat(service.serveBody(REF, "alice", "default").blockOptional())
                    .as("stored type %s must never serve", vector)
                    .isEmpty();
        }
    }

    @Test
    void serveableTypes_areExactlyWhatTheUploadSniffCanRecord() {
        // Drift guard: the allowlist is a mirror of ImageSniffer's real output, derived
        // by SNIFFING actual magic bytes rather than by copying a list. Teach the sniffer
        // a new raster and this fails until the serve allowlist learns it too; the
        // reverse (an allowlist entry the sniffer can never produce) fails as well.
        Set<String> sniffable = new LinkedHashSet<>();
        for (byte[] sample : List.of(
                new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0},
                new byte[]{(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10, 0, 0, 0, 0},
                new byte[]{'G', 'I', 'F', '8', '9', 'a', 0, 0, 0, 0, 0, 0},
                new byte[]{'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'E', 'B', 'P'},
                new byte[]{'B', 'M', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})) {
            String type = ImageSniffer.detect(sample);
            assertThat(type).as("sample must sniff as a raster").isNotNull();
            sniffable.add(type);
        }
        assertThat(CharacterAvatarService.SERVEABLE_TYPES).isEqualTo(sniffable);
        // and the vector the platform refuses is not in it, by construction.
        assertThat(ImageSniffer.detect("<svg xmlns=\"http://www.w3.org/2000/svg\"/>".getBytes()))
                .isNull();
        assertThat(CharacterAvatarService.SERVEABLE_TYPES).doesNotContain("image/svg+xml");
    }

    @Test
    void serveBody_blankHandle_neverReachesTheStore() {
        when(profiles.findAvatarBodyByRef(eq(""))).thenReturn(Mono.empty());
        assertThat(service.serveBody("", "bob", "default").blockOptional()).isEmpty();
    }
}
