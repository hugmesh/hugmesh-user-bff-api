package systems.snapdragon.userbff.profile;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

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
 * {@link UserProfileRepository}. Verifies the upload→store→return contract: the
 * uploaded {@code mxc://} URL is persisted onto the OWNER's avatar_url (owner +
 * domain scoped) and returned, and a blank owner is rejected before any upload.
 */
class AvatarServiceTest {

    private final MatrixMediaClient media = mock(MatrixMediaClient.class);
    private final UserProfileRepository repo = mock(UserProfileRepository.class);
    private final AvatarService service = new AvatarService(media, repo);

    @Test
    void uploadAndStore_uploadsThenPersistsMxc_andReturnsIt() {
        byte[] bytes = {1, 2, 3};
        when(media.upload(eq("alice"), eq(bytes), eq("image/png")))
                .thenReturn(Mono.just("mxc://home/abc"));
        when(repo.updateAvatarUrl(eq("alice"), eq("mxc://home/abc"), eq("default")))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(service.uploadAndStore("alice", bytes, "image/png", "default"))
                .expectNext("mxc://home/abc")
                .verifyComplete();

        // the upload result is the EXACT value persisted onto the owner's avatar_url
        ArgumentCaptor<String> mxc = ArgumentCaptor.forClass(String.class);
        verify(repo).updateAvatarUrl(eq("alice"), mxc.capture(), eq("default"));
        assertThat(mxc.getValue()).isEqualTo("mxc://home/abc");
    }

    @Test
    void uploadAndStore_blankOwner_isRejected_noUpload() {
        assertThatThrownBy(() -> service.uploadAndStore("  ", new byte[]{1}, "image/png", "default"))
                .isInstanceOf(IllegalArgumentException.class);
        verify(media, never()).upload(anyString(), any(), anyString());
        verify(repo, never()).updateAvatarUrl(anyString(), anyString(), any());
    }

    @Test
    void uploadAndStore_nullOwner_isRejected() {
        assertThatThrownBy(() -> service.uploadAndStore(null, new byte[]{1}, "image/png", "default"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
