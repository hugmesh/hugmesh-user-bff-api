package systems.snapdragon.userbff.character;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.userbff.federation.FederationApiClient;
import systems.snapdragon.userbff.federation.FederationModerationModels.FindingRequest;
import systems.snapdragon.userbff.profile.EdgeAiAnalysisClient;
import systems.snapdragon.userbff.profile.MatrixMediaClient;
import systems.snapdragon.userbff.profile.ModerationVerdict;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for {@link StickerService} with a mocked {@link EdgeAiAnalysisClient} +
 * {@link MatrixMediaClient} + {@link VnStickerRepository} + {@link FederationApiClient}.
 * Proves the MODERATE → UPLOAD → STORE-PENDING → FILE-MODERATION-FINDING leg (the avatar
 * seam, reused for stickers):
 * <ul>
 *   <li>an ALLOWED sticker is uploaded, stored status=PENDING with the mxc:// + expression,
 *       and a held {@code @system} finding (surface=character-sticker, disposition=flagged)
 *       is filed;</li>
 *   <li>a BLOCKED (reject/flag) sticker never reaches the homeserver and is never persisted
 *       (422), and IS filed as a held finding (reject→rejected / flag→flagged) with the
 *       verdict fields;</li>
 *   <li>a federation outage does NOT fail the save (fail-soft) — the sticker still returns;</li>
 *   <li>a non-canonical expression is a 422 — nothing moderated/uploaded/stored;</li>
 *   <li>the owner is required (blank/null → IllegalArgumentException, nothing moderated).</li>
 * </ul>
 */
class StickerServiceTest {

    private final EdgeAiAnalysisClient moderation = mock(EdgeAiAnalysisClient.class);
    private final MatrixMediaClient media = mock(MatrixMediaClient.class);
    private final VnStickerRepository repo = mock(VnStickerRepository.class);
    private final FederationApiClient federation = mock(FederationApiClient.class);
    private final StickerService service = new StickerService(moderation, media, repo, federation);

    @BeforeEach
    void allowByDefault() {
        // Moderation OFF (dark default) ⇒ allow — the upload flow is unchanged.
        when(moderation.moderate(any())).thenReturn(Mono.just(ModerationVerdict.allow()));
    }

    private static VnSticker storedSticker(String expression, String mxc) {
        return new VnSticker("st-1", "alice", "default", expression, mxc, "PENDING", null, Instant.now());
    }

    @Test
    void save_allowed_uploadsStoresPending_capturesFindingId() {
        byte[] png = {(byte) 0x89, 'P', 'N', 'G'};
        when(media.upload(eq("alice"), eq(png), eq("image/png"))).thenReturn(Mono.just("mxc://home/h1"));
        when(repo.save(eq("alice"), eq("default"), eq("happy"), eq("mxc://home/h1"), eq("PENDING")))
                .thenReturn(Mono.just(storedSticker("happy", "mxc://home/h1")));
        // federation returns the created finding with an id; the service writes it back.
        when(federation.fileFinding(any())).thenReturn(Mono.just(Map.of("id", 7L, "status", "held")));
        when(repo.setFindingId(eq("st-1"), eq("alice"), eq(7L))).thenReturn(Mono.just(1));

        VnSticker out = service.save("alice", "default", "happy", png, "image/png").block();
        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo("PENDING");
        assertThat(out.mxcUrl()).isEqualTo("mxc://home/h1");
        assertThat(out.expression()).isEqualTo("happy");

        // the mxc:// + expression are persisted PENDING for the owner.
        verify(media).upload(eq("alice"), eq(png), eq("image/png"));
        verify(repo).save(eq("alice"), eq("default"), eq("happy"), eq("mxc://home/h1"), eq("PENDING"));

        // ...a held finding is filed: surface=character-sticker, disposition=flagged,
        // verdict fields absent (the bytes passed the auto-classifier; a human reviews) and
        // the just-saved row id is passed as the finding subjectRef (the producer back-link).
        ArgumentCaptor<FindingRequest> req = ArgumentCaptor.forClass(FindingRequest.class);
        verify(federation).fileFinding(req.capture());
        assertThat(req.getValue().surface()).isEqualTo("character-sticker");
        assertThat(req.getValue().disposition()).isEqualTo("flagged");
        assertThat(req.getValue().classification()).isNull();
        assertThat(req.getValue().confidence()).isNull();
        assertThat(req.getValue().policyHit()).isNull();
        assertThat(req.getValue().perceptualHash()).isNull();
        assertThat(req.getValue().subjectRef()).isEqualTo("st-1");

        // ...and the returned federation finding id (7) is written back onto the row.
        verify(repo).setFindingId(eq("st-1"), eq("alice"), eq(7L));
    }

    @Test
    void save_policyRejected_isBlocked_filesRejectedFinding_noUploadNoPersist() {
        when(moderation.moderate(any()))
                .thenReturn(Mono.just(new ModerationVerdict("reject", "nsfw", 0.95, true, "ab12")));
        when(federation.fileFinding(any())).thenReturn(Mono.just(Map.of("status", "held")));

        StepVerifier.create(service.save("alice", "default", "happy", new byte[]{1}, "image/png"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ApiException.class)
                        .hasMessageContaining("blocked by content policy"))
                .verify();

        // A blocked sticker never reaches the homeserver and is never persisted.
        verify(media, never()).upload(anyString(), any(), anyString());
        verify(repo, never()).save(anyString(), any(), anyString(), anyString(), anyString());
        // ...but it IS filed as a held finding, disposition=rejected, with the verdict fields.
        ArgumentCaptor<FindingRequest> req = ArgumentCaptor.forClass(FindingRequest.class);
        verify(federation).fileFinding(req.capture());
        assertThat(req.getValue().surface()).isEqualTo("character-sticker");
        assertThat(req.getValue().disposition()).isEqualTo("rejected");
        assertThat(req.getValue().classification()).isEqualTo("nsfw");
        assertThat(req.getValue().confidence()).isEqualTo(0.95);
        assertThat(req.getValue().policyHit()).isTrue();
        assertThat(req.getValue().perceptualHash()).isEqualTo("ab12");
        // a BLOCKED sticker is never persisted, so there is no row id to back-link.
        assertThat(req.getValue().subjectRef()).isNull();
        // ...and no row exists to stamp.
        verify(repo, never()).setFindingId(anyString(), anyString(), any());
    }

    @Test
    void save_flagged_isAlsoBlocked_filesFlaggedFinding() {
        when(moderation.moderate(any()))
                .thenReturn(Mono.just(new ModerationVerdict("flag", "nsfw", 0.6, true, null)));
        when(federation.fileFinding(any())).thenReturn(Mono.just(Map.of("status", "held")));

        StepVerifier.create(service.save("alice", "default", "sad", new byte[]{9}, "image/png"))
                .expectError(ApiException.class)
                .verify();
        verify(media, never()).upload(anyString(), any(), anyString());
        // flag maps to disposition=flagged
        ArgumentCaptor<FindingRequest> req = ArgumentCaptor.forClass(FindingRequest.class);
        verify(federation).fileFinding(req.capture());
        assertThat(req.getValue().disposition()).isEqualTo("flagged");
    }

    @Test
    void save_findingFileFails_onAllowedSticker_stillStored_failSoft() {
        byte[] png = {(byte) 0x89, 'P', 'N', 'G'};
        when(media.upload(eq("alice"), any(), eq("image/png"))).thenReturn(Mono.just("mxc://home/h2"));
        when(repo.save(eq("alice"), eq("default"), eq("wink"), eq("mxc://home/h2"), eq("PENDING")))
                .thenReturn(Mono.just(storedSticker("wink", "mxc://home/h2")));
        // federation is unreachable — the finding-file errors, but the save must still succeed.
        when(federation.fileFinding(any()))
                .thenReturn(Mono.error(new RuntimeException("federation unreachable")));

        StepVerifier.create(service.save("alice", "default", "wink", png, "image/png"))
                .assertNext(s -> {
                    assertThat(s.status()).isEqualTo("PENDING");
                    assertThat(s.mxcUrl()).isEqualTo("mxc://home/h2");
                })
                .verifyComplete();
        // the sticker WAS stored despite the federation outage.
        verify(repo).save(eq("alice"), eq("default"), eq("wink"), eq("mxc://home/h2"), eq("PENDING"));
    }

    @Test
    void save_findingFileFails_onBlockedSticker_stillBlocked_failSoft() {
        when(moderation.moderate(any()))
                .thenReturn(Mono.just(new ModerationVerdict("reject", "abuse", 0.99, true, null)));
        when(federation.fileFinding(any()))
                .thenReturn(Mono.error(new RuntimeException("federation unreachable")));

        StepVerifier.create(service.save("alice", "default", "angry", new byte[]{7}, "image/png"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ApiException.class)
                        .hasMessageContaining("blocked by content policy"))
                .verify();
        verify(media, never()).upload(anyString(), any(), anyString());
    }

    @Test
    void save_nonCanonicalExpression_is422_nothingModerated() {
        StepVerifier.create(service.save("alice", "default", "not-an-expression", new byte[]{1}, "image/png"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ApiException.class)
                        .hasMessageContaining("canonical"))
                .verify();
        verify(moderation, never()).moderate(any());
        verify(media, never()).upload(anyString(), any(), anyString());
        verify(repo, never()).save(anyString(), any(), anyString(), anyString(), anyString());
    }

    @Test
    void save_blankOwner_isRejected_nothingModerated() {
        assertThatThrownBy(() -> service.save("  ", "default", "happy", new byte[]{1}, "image/png"))
                .isInstanceOf(IllegalArgumentException.class);
        verify(moderation, never()).moderate(any());
        verify(media, never()).upload(anyString(), any(), anyString());
    }

    @Test
    void save_nullOwner_isRejected() {
        assertThatThrownBy(() -> service.save(null, "default", "happy", new byte[]{1}, "image/png"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void listMine_delegatesOwnerAndDomainScoped() {
        when(repo.listForOwner("alice", "default"))
                .thenReturn(Flux.just(storedSticker("happy", "mxc://h/1")));
        assertThat(service.listMine("alice", "default").collectList().block()).hasSize(1);
        verify(repo).listForOwner("alice", "default");
    }

    @Test
    void getOwned_delegatesOwnerScopedLookup() {
        when(repo.findOwned("st-1", "alice")).thenReturn(Mono.just(storedSticker("happy", "mxc://h/1")));
        assertThat(service.getOwned("st-1", "alice").block()).isNotNull();
        verify(repo).findOwned("st-1", "alice");
    }
}
