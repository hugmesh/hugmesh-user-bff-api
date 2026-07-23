package systems.hugmesh.userbff.silence;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Parameter;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * STRUCTURAL distinctness guard for the self-silence invariant: a self-silence is
 * NOT a ban, and {@link SelfSilenceService} is enforced to be structurally incapable
 * of revoking a token, removing a Casdoor role, or writing a suspension. This test
 * inspects the service's collaborators (constructor parameter types) and fails if any
 * revocation / suspension / Casdoor-role-mutating client is ever wired in — so a
 * future change that tries to give self-silence ban powers breaks the build.
 */
class SelfSilenceDistinctnessTest {

    /** Substrings of type names that would betray ban capability if injected. */
    private static final String[] FORBIDDEN = {
            "revocation", "suspension", "suspend", "ban", "casdooradmin", "rolemutat"
    };

    @Test
    void selfSilenceService_hasNoBanCapableCollaborator() {
        Constructor<?>[] ctors = SelfSilenceService.class.getDeclaredConstructors();
        assertThat(ctors).hasSize(1);
        for (Parameter p : ctors[0].getParameters()) {
            String typeName = p.getType().getName().toLowerCase();
            // the generic List<HomeserverHideClient> erases to List; check the param type name only
            for (String forbidden : FORBIDDEN) {
                assertThat(typeName)
                        .as("SelfSilenceService must not be injected with a %s client (it is NOT a ban)", forbidden)
                        .doesNotContain(forbidden);
            }
        }
    }

    @Test
    void selfSilenceService_collaboratorsAreOnlyTheExpectedHideSeams() {
        Constructor<?> ctor = SelfSilenceService.class.getDeclaredConstructors()[0];
        var typeNames = Arrays.stream(ctor.getParameterTypes()).map(Class::getSimpleName).toList();
        // repo + federation client + the list of hide seams + the federation-enabled flag.
        assertThat(typeNames).containsExactlyInAnyOrder(
                "SelfSilenceRepository", "FederationApiClient", "List", "boolean");
    }
}
