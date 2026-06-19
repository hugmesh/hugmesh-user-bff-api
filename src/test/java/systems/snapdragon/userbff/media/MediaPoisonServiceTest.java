package systems.snapdragon.userbff.media;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.media.MediaPoisonService.UploadOutcome;
import systems.snapdragon.userbff.media.PoisonModels.Backend;
import systems.snapdragon.userbff.media.PoisonModels.Health;
import systems.snapdragon.userbff.media.PoisonModels.PoisonResult;
import systems.snapdragon.userbff.media.PoisonModels.SurvivalVerdict;
import systems.snapdragon.commons.web.ApiException;

import java.time.Instant;
import java.util.List;
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
 * Unit test for the {@link MediaPoisonService} orchestration with the worker +
 * homeserver clients + repository MOCKED. Proves the spec'd decision table:
 * <ul>
 *   <li>mode=none (opt-out) / non-image → forward-through UNCHANGED, status=none,
 *       worker NEVER called;</li>
 *   <li>image + cloak, worker PRESENT, survival passes → real homeserver upload of
 *       the POISONED bytes + status=protected (only after the round-trip gate);</li>
 *   <li>image + cloak, worker present, survival FAILS → status=degraded (badge never
 *       lies);</li>
 *   <li>worker ABSENT (heavy tier not present) → forward original + status=skipped;</li>
 *   <li>worker present but poison FAILS → forward original + status=failed.</li>
 * </ul>
 */
class MediaPoisonServiceTest {

    private MediaPoisonDecisionRepository repo;
    private PoisonWorkerClient worker;
    private HomeserverMediaClient homeserver;
    private MediaPoisoningProperties props;
    private MediaPoisonService service;

    /** A minimal valid PNG header so the magic-byte sniffer classifies it as an image. */
    private static byte[] pngBytes() {
        byte[] b = new byte[64];
        int[] head = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        for (int i = 0; i < head.length; i++) b[i] = (byte) head[i];
        return b;
    }

    @BeforeEach
    void setUp() {
        repo = mock(MediaPoisonDecisionRepository.class);
        worker = mock(PoisonWorkerClient.class);
        homeserver = mock(HomeserverMediaClient.class);
        props = new MediaPoisoningProperties();
        props.setEnabled(true);
        props.setDefaultMode("glaze");
        props.setThumbnailSizes(List.of("small", "240x240"));
        service = new MediaPoisonService(repo, worker, homeserver, props);

        // the repository echoes a decision back (id + ts filled) so outcomes carry status.
        // The 7th arg is the domain (server-derived); the upload back-compat overload
        // used by these tests passes the platform 'default' domain.
        when(repo.record(anyString(), anyString(), any(), anyString(), anyString(), any(), anyString()))
                .thenAnswer(inv -> Mono.just(new MediaPoisonDecision(
                        "dec-id", inv.getArgument(0), inv.getArgument(1), inv.getArgument(2),
                        inv.getArgument(3), inv.getArgument(4), inv.getArgument(5), Instant.now())));
    }

    private static Map<String, Object> mastodonResp() {
        return Map.of("id", "media-77", "url", "/media/orig.png", "preview_url", "/media/small.png");
    }

    @Test
    void optOut_forwardsThrough_statusNone_workerNeverCalled() {
        when(homeserver.upload(eq("mastodon"), any(), any(), any())).thenReturn(Mono.just(mastodonResp()));

        UploadOutcome out = service.upload("alice", "mastodon", "none",
                pngBytes(), "a.png", "image/png").block();

        assertThat(out.decision().status()).isEqualTo("none");
        assertThat(out.homeserver()).containsEntry("id", "media-77");
        verify(worker, never()).capability();
        verify(worker, never()).poison(any(), any(), any(), any(), any());
        verify(repo).record(eq("alice"), eq("mastodon"), eq("media-77"), eq("none"), eq("none"), any(), eq("default"));
    }

    @Test
    void nonImage_forwardsThrough_statusNone_evenWhenModeGlaze() {
        when(homeserver.upload(eq("mastodon"), any(), any(), any())).thenReturn(Mono.just(mastodonResp()));

        UploadOutcome out = service.upload("alice", "mastodon", "glaze",
                "<html>not an image</html>".getBytes(), "x.html", "image/png").block();

        // sniffed as non-image -> forward-through regardless of the requested mode.
        assertThat(out.decision().status()).isEqualTo("none");
        verify(worker, never()).capability();
    }

    @Test
    void workerAbsent_forwardsOriginal_statusSkipped() {
        when(worker.capability()).thenReturn(Mono.just(absent()));
        when(homeserver.upload(eq("mastodon"), any(), any(), any())).thenReturn(Mono.just(mastodonResp()));

        UploadOutcome out = service.upload("alice", "mastodon", "glaze",
                pngBytes(), "a.png", "image/png").block();

        assertThat(out.decision().status()).isEqualTo("skipped");
        assertThat(out.decision().backend()).isEqualTo("none");
        verify(worker, never()).poison(any(), any(), any(), any(), any());
        verify(repo).record(eq("alice"), eq("mastodon"), eq("media-77"), eq("glaze"), eq("skipped"), eq("none"), eq("default"));
    }

    @Test
    void cloak_survivalPasses_statusProtected_uploadsPoisonedBytes() {
        when(worker.capability()).thenReturn(Mono.just(present("cuda")));
        when(worker.poison(any(), eq("glaze"), any(), any(), any()))
                .thenReturn(Mono.just(new PoisonResult(true, "cuda", "CLOAKED".getBytes(), List.of(), null)));
        when(homeserver.upload(eq("mastodon"), any(), any(), any())).thenReturn(Mono.just(mastodonResp()));
        // served re-fetch returns bytes; survival check says the cloak survived.
        when(homeserver.fetchServed(eq("mastodon"), anyString())).thenReturn(Mono.just("SERVED".getBytes()));
        when(worker.checkSurvival(any(), eq("glaze"), any()))
                .thenReturn(Mono.just(new SurvivalVerdict(true, 0.9, null)));

        ArgumentCaptor<byte[]> uploaded = ArgumentCaptor.forClass(byte[].class);
        UploadOutcome out = service.upload("alice", "mastodon", "glaze",
                pngBytes(), "a.png", "image/png").block();

        assertThat(out.decision().status()).isEqualTo("protected");
        assertThat(out.decision().backend()).isEqualTo("cuda");
        // the REAL homeserver upload used the POISONED bytes, not the original.
        verify(homeserver).upload(eq("mastodon"), uploaded.capture(), any(), any());
        assertThat(new String(uploaded.getValue())).isEqualTo("CLOAKED");
        verify(repo).record(eq("alice"), eq("mastodon"), eq("media-77"), eq("glaze"), eq("protected"), eq("cuda"), eq("default"));
    }

    @Test
    void cloak_survivalFails_statusDegraded() {
        when(worker.capability()).thenReturn(Mono.just(present("rocm")));
        when(worker.poison(any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new PoisonResult(true, "rocm", "CLOAKED".getBytes(), List.of(), null)));
        when(homeserver.upload(eq("mastodon"), any(), any(), any())).thenReturn(Mono.just(mastodonResp()));
        when(homeserver.fetchServed(eq("mastodon"), anyString())).thenReturn(Mono.just("SERVED".getBytes()));
        // the perturbation washed out in the homeserver re-encode -> not present.
        when(worker.checkSurvival(any(), any(), any()))
                .thenReturn(Mono.just(new SurvivalVerdict(false, 0.1, "washed out")));

        UploadOutcome out = service.upload("alice", "mastodon", "glaze",
                pngBytes(), "a.png", "image/png").block();

        assertThat(out.decision().status()).isEqualTo("degraded");
        verify(repo).record(eq("alice"), eq("mastodon"), eq("media-77"), eq("glaze"), eq("degraded"), eq("rocm"), eq("default"));
    }

    @Test
    void cloak_workerPoisonFails_forwardsOriginal_statusFailed() {
        when(worker.capability()).thenReturn(Mono.just(present("cuda")));
        // worker returned ok=false (or could not cloak) -> the service must NOT claim protection.
        when(worker.poison(any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new PoisonResult(false, "cuda", null, List.of(), "oom")));
        when(homeserver.upload(eq("mastodon"), any(), any(), any())).thenReturn(Mono.just(mastodonResp()));

        ArgumentCaptor<byte[]> uploaded = ArgumentCaptor.forClass(byte[].class);
        UploadOutcome out = service.upload("alice", "mastodon", "glaze",
                pngBytes(), "a.png", "image/png").block();

        assertThat(out.decision().status()).isEqualTo("failed");
        // forwarded the ORIGINAL (png header), not poisoned bytes.
        verify(homeserver).upload(eq("mastodon"), uploaded.capture(), any(), any());
        assertThat(uploaded.getValue()[1]).isEqualTo((byte) 'P'); // PNG magic survived = original.
        verify(worker, never()).checkSurvival(any(), any(), any());
    }

    @Test
    void featureDisabled_forwardsThrough_statusNone() {
        props.setEnabled(false);
        when(homeserver.upload(eq("matrix"), any(), any(), any()))
                .thenReturn(Mono.just(Map.of("content_uri", "mxc://home/abc")));

        UploadOutcome out = service.upload("alice", "matrix", "glaze",
                pngBytes(), "a.png", "image/png").block();

        assertThat(out.decision().status()).isEqualTo("none");
        assertThat(out.decision().mediaRef()).isEqualTo("mxc://home/abc");
        verify(worker, never()).capability();
    }

    @Test
    void badPlatform_isBadRequest() {
        assertThatThrownBy(() -> service.upload("alice", "bluesky", "glaze",
                pngBytes(), "a.png", "image/png").block())
                .isInstanceOf(ApiException.class);
    }

    @Test
    void status_ownerScoped_notFoundWhenAbsent() {
        when(repo.findByOwnerAndRef(eq("alice"), eq("ref-x"), eq("default"))).thenReturn(Mono.empty());
        assertThatThrownBy(() -> service.status("alice", "ref-x").block())
                .isInstanceOf(ApiException.class);
    }

    // ── helpers ──────────────────────────────────────────────────────────
    private static Health absent() {
        return new Health(Backend.NONE.wire(), List.of(), null);
    }
    private static Health present(String backend) {
        return new Health(backend, List.of("glaze", "nightshade"), 60);
    }
}
