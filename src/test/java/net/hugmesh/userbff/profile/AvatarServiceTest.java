package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.federation.FederationApiClient;
import net.hugmesh.userbff.federation.FederationModerationModels.FindingRequest;

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
 * Unit test for {@link AvatarService} with a mocked {@link MatrixMediaClient} +
 * {@link UserProfileRepository} + {@link EdgeAiAnalysisClient} + {@link FederationApiClient}.
 * Verifies the upload→store→return contract (the uploaded {@code mxc://} URL is persisted
 * onto the OWNER's avatar_url, owner + domain scoped, and returned), and the A3 producer
 * behaviour: a BLOCKED image is filed as a held {@code @system} finding (flag→flagged /
 * reject→rejected) before the 422, fail-soft if federation errors, and never filed when allowed.
 */
class AvatarServiceTest {

    private final MatrixMediaClient media = mock(MatrixMediaClient.class);
    private final UserProfileRepository repo = mock(UserProfileRepository.class);
    private final EdgeAiAnalysisClient moderation = mock(EdgeAiAnalysisClient.class);
    private final FederationApiClient federation = mock(FederationApiClient.class);
    private final AvatarService service = new AvatarService(media, repo, moderation, federation);

    @BeforeEach
    void allowByDefault() {
        // Moderation OFF (dark default) ⇒ allow — the upload flow is unchanged.
        when(moderation.moderate(any())).thenReturn(Mono.just(ModerationVerdict.allow()));
    }

    @Test
    void uploadAndStore_uploadsThenPersistsMxc_andReturnsIt() {
        byte[] bytes = {1, 2, 3};
        when(media.upload(eq("alice"), eq(bytes), eq("image/png")))
                .thenReturn(Mono.just("mxc://home/abc"));
        when(repo.updateAvatarUrl(eq("alice"), eq("mxc://home/abc"), eq("default"), any(), any()))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(service.uploadAndStore("alice", bytes, "image/png", "default"))
                .expectNext("mxc://home/abc")
                .verifyComplete();

        // the upload result is the EXACT value persisted onto the owner's avatar_url
        ArgumentCaptor<String> mxc = ArgumentCaptor.forClass(String.class);
        verify(repo).updateAvatarUrl(eq("alice"), mxc.capture(), eq("default"), any(), any());
        assertThat(mxc.getValue()).isEqualTo("mxc://home/abc");
        // an allowed image is NEVER filed as a finding
        verify(federation, never()).fileFinding(any());
    }

    @Test
    void uploadAndStore_policyRejectedImage_isBlocked_filesRejectedFinding_noUploadNoPersist() {
        byte[] bytes = {1, 2, 3};
        when(moderation.moderate(any()))
                .thenReturn(Mono.just(new ModerationVerdict("reject", "nsfw", 0.95, true, "ab12")));
        when(federation.fileFinding(any())).thenReturn(Mono.just(Map.of("status", "held")));

        StepVerifier.create(service.uploadAndStore("alice", bytes, "image/png", "default"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ApiException.class)
                        .hasMessageContaining("blocked by content policy"))
                .verify();

        // A blocked avatar never reaches the homeserver and is never persisted.
        verify(media, never()).upload(anyString(), any(), anyString());
        verify(repo, never()).updateAvatarUrl(anyString(), anyString(), any(), any(), any());
        // ...but it IS filed as a held finding, disposition=rejected, with the verdict fields.
        ArgumentCaptor<FindingRequest> req = ArgumentCaptor.forClass(FindingRequest.class);
        verify(federation).fileFinding(req.capture());
        assertThat(req.getValue().surface()).isEqualTo("profile-avatar");
        assertThat(req.getValue().disposition()).isEqualTo("rejected");
        assertThat(req.getValue().classification()).isEqualTo("nsfw");
        assertThat(req.getValue().confidence()).isEqualTo(0.95);
        assertThat(req.getValue().policyHit()).isTrue();
        assertThat(req.getValue().perceptualHash()).isEqualTo("ab12");
    }

    @Test
    void uploadAndStore_flaggedImage_isAlsoBlocked_filesFlaggedFinding() {
        when(moderation.moderate(any()))
                .thenReturn(Mono.just(new ModerationVerdict("flag", "nsfw", 0.6, true, null)));
        when(federation.fileFinding(any())).thenReturn(Mono.just(Map.of("status", "held")));

        StepVerifier.create(service.uploadAndStore("alice", new byte[]{9}, "image/png", "default"))
                .expectError(ApiException.class)
                .verify();
        verify(media, never()).upload(anyString(), any(), anyString());
        // flag maps to disposition=flagged
        ArgumentCaptor<FindingRequest> req = ArgumentCaptor.forClass(FindingRequest.class);
        verify(federation).fileFinding(req.capture());
        assertThat(req.getValue().disposition()).isEqualTo("flagged");
    }

    @Test
    void uploadAndStore_findingFileFails_imageStillBlocked_failSoft() {
        when(moderation.moderate(any()))
                .thenReturn(Mono.just(new ModerationVerdict("reject", "abuse", 0.99, true, null)));
        // federation is unreachable — the finding-file errors, but the image stays blocked.
        when(federation.fileFinding(any()))
                .thenReturn(Mono.error(new RuntimeException("federation unreachable")));

        StepVerifier.create(service.uploadAndStore("alice", new byte[]{7}, "image/png", "default"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ApiException.class)
                        .hasMessageContaining("blocked by content policy"))
                .verify();
        verify(media, never()).upload(anyString(), any(), anyString());
    }

    @Test
    void uploadAndStore_allowedImage_proceedsToUpload_noFinding() {
        byte[] bytes = {4, 5};
        when(moderation.moderate(any())).thenReturn(Mono.just(ModerationVerdict.allow()));
        when(media.upload(eq("bob"), eq(bytes), eq("image/jpeg"))).thenReturn(Mono.just("mxc://h/ok"));
        when(repo.updateAvatarUrl(eq("bob"), eq("mxc://h/ok"), eq("default"), any(), any())).thenReturn(Mono.just(1L));

        StepVerifier.create(service.uploadAndStore("bob", bytes, "image/jpeg", "default"))
                .expectNext("mxc://h/ok")
                .verifyComplete();
        verify(federation, never()).fileFinding(any());
    }

    @Test
    void uploadAndStore_blankOwner_isRejected_noUpload() {
        assertThatThrownBy(() -> service.uploadAndStore("  ", new byte[]{1}, "image/png", "default"))
                .isInstanceOf(IllegalArgumentException.class);
        verify(media, never()).upload(anyString(), any(), anyString());
        verify(repo, never()).updateAvatarUrl(anyString(), anyString(), any(), any(), any());
    }

    @Test
    void uploadAndStore_nullOwner_isRejected() {
        assertThatThrownBy(() -> service.uploadAndStore(null, new byte[]{1}, "image/png", "default"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
