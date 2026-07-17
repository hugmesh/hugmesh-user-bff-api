package systems.snapdragon.userbff.media;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import systems.snapdragon.userbff.auth.AdminBffInternalClient.AccountView;
import systems.snapdragon.userbff.auth.CasdoorLoginClient.CasdoorLoginResult;
import systems.snapdragon.userbff.auth.SsoAuthController.MfaChallenge;
import systems.snapdragon.userbff.media.PoisonModels.Health;
import systems.snapdragon.userbff.media.PoisonModels.PoisonRequest;
import systems.snapdragon.userbff.media.PoisonModels.PoisonResult;
import systems.snapdragon.userbff.media.PoisonModels.SizedBytes;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the constructor-side defensive copies actually bite.
 *
 * <p>Each case is the EI_EXPOSE_REP2 leak in its executable form: build the carrier from a
 * mutable input, then MUTATE THE CALLER'S OWN REFERENCE afterwards and assert the carrier
 * did not change. Without the copy-on-the-way-in, the field stays aliased to the caller's
 * object and every one of these assertions fails — the copy-on-the-way-out accessors that
 * already existed cannot prevent it, which is exactly why the finding was real.
 */
class DefensiveCopyTest {

    @Test
    @DisplayName("SizedBytes: mutating the caller's byte[] after construction does not change the record")
    void sizedBytesIsInsulatedFromCallerMutation() {
        byte[] callerOwned = {1, 2, 3};
        SizedBytes sut = new SizedBytes("small", callerOwned);

        callerOwned[0] = 99;

        assertThat(sut.bytes()).containsExactly(1, 2, 3);
    }

    @Test
    @DisplayName("PoisonResult: caller cannot mutate the poisoned original or the thumbnail list")
    void poisonResultIsInsulatedFromCallerMutation() {
        byte[] original = {10, 20};
        List<SizedBytes> thumbs = new ArrayList<>(List.of(new SizedBytes("small", new byte[]{7})));
        PoisonResult sut = new PoisonResult(true, "gpu", original, thumbs, null);

        original[0] = 99;
        thumbs.clear();

        assertThat(sut.poisonedOriginal()).containsExactly(10, 20);
        assertThat(sut.thumbnails()).hasSize(1);
    }

    @Test
    @DisplayName("PoisonRequest: caller cannot mutate the image bytes or the requested sizes")
    void poisonRequestIsInsulatedFromCallerMutation() {
        byte[] image = {5, 6};
        List<String> sizes = new ArrayList<>(List.of("small"));
        PoisonRequest sut = new PoisonRequest("mode", "f.png", "image/png", sizes, image);

        image[0] = 99;
        sizes.add("240x240");

        assertThat(sut.imageBase64NotUsed()).containsExactly(5, 6);
        assertThat(sut.thumbnailSizes()).containsExactly("small");
    }

    @Test
    @DisplayName("Health: caller cannot mutate the advertised modes")
    void healthIsInsulatedFromCallerMutation() {
        List<String> modes = new ArrayList<>(List.of("cloak"));
        Health sut = new Health("gpu", modes, 5);

        modes.add("injected");

        assertThat(sut.modes()).containsExactly("cloak");
    }

    @Test
    @DisplayName("AccountView: caller cannot inject a role after the view is built")
    void accountViewRolesAreInsulatedFromCallerMutation() {
        List<String> roles = new ArrayList<>(List.of("user"));
        AccountView sut = new AccountView("id", "casdoor", "handle", true, roles, "lp");

        roles.add("superadmin");

        assertThat(sut.roles()).containsExactly("user");
    }

    @Test
    @DisplayName("CasdoorLoginResult: caller cannot mutate the offered MFA types")
    void casdoorLoginResultIsInsulatedFromCallerMutation() {
        List<String> types = new ArrayList<>(List.of("totp"));
        CasdoorLoginResult sut = new CasdoorLoginResult(CasdoorLoginResult.Kind.MFA_REQUIRED,
                null, types, null);

        types.add("sms");

        assertThat(sut.mfaTypes()).containsExactly("totp");
    }

    @Test
    @DisplayName("MfaChallenge: caller cannot mutate the challenge body's MFA types")
    void mfaChallengeIsInsulatedFromCallerMutation() {
        List<String> types = new ArrayList<>(List.of("totp"));
        MfaChallenge sut = new MfaChallenge(true, types);

        types.add("sms");

        assertThat(sut.mfaType()).containsExactly("totp");
    }

    @Test
    @DisplayName("MediaPoisoningProperties: the binder-supplied list cannot be mutated post-bind")
    void thumbnailSizesPropertyIsInsulatedFromCallerMutation() {
        List<String> bound = new ArrayList<>(List.of("small"));
        MediaPoisoningProperties sut = new MediaPoisoningProperties();
        sut.setThumbnailSizes(bound);

        bound.add("injected");

        assertThat(sut.getThumbnailSizes()).containsExactly("small");
    }

    @Test
    @DisplayName("UploadOutcome: the unmodifiable view is backed by a COPY, not the caller's map")
    void uploadOutcomeIsInsulatedFromCallerMutation() {
        Map<String, Object> hs = new LinkedHashMap<>(Map.of("content_uri", "mxc://x"));
        MediaPoisonService.UploadOutcome sut = new MediaPoisonService.UploadOutcome(hs, null);

        hs.put("content_uri", "mxc://attacker");

        assertThat(sut.homeserver()).containsEntry("content_uri", "mxc://x");
    }

    @Test
    @DisplayName("UploadOutcome tolerates a null JSON value (Map.copyOf would reject it)")
    void uploadOutcomeToluceratesNullValues() {
        Map<String, Object> hs = new LinkedHashMap<>();
        hs.put("url", null);

        MediaPoisonService.UploadOutcome sut = new MediaPoisonService.UploadOutcome(hs, null);

        assertThat(sut.homeserver()).containsEntry("url", null);
    }
}
