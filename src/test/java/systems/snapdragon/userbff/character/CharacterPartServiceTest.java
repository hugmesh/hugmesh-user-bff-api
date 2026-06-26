package systems.snapdragon.userbff.character;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.userbff.federation.FederationApiClient;
import systems.snapdragon.userbff.federation.FederationModerationModels.FindingRequest;
import systems.snapdragon.userbff.svg.SvgSanitizerService;

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
 * Unit test for {@link CharacterPartService}. The REAL {@link SvgSanitizerService} is
 * used (it is pure-JDK and is the security boundary under test); the
 * {@link VnCharacterPartRepository} + {@link FederationApiClient} are mocked. Proves the
 * SANITIZE → STORE-PENDING → FILE-MODERATION-FINDING leg:
 * <ul>
 *   <li>a valid SVG is sanitized (script stripped), stored with status=PENDING + the
 *       SANITIZED svg, and a held {@code @system} finding (surface=character-part,
 *       disposition=flagged) is filed;</li>
 *   <li>a malformed / non-svg body is a 422 ({@link ApiException}) — NOTHING stored, NO
 *       finding filed;</li>
 *   <li>a federation outage does NOT fail the save (fail-soft) — the part still returns;</li>
 *   <li>the owner is required (blank/null → IllegalArgumentException, nothing stored).</li>
 * </ul>
 */
class CharacterPartServiceTest {

    private final SvgSanitizerService sanitizer = new SvgSanitizerService();
    private final VnCharacterPartRepository repo = mock(VnCharacterPartRepository.class);
    private final FederationApiClient federation = mock(FederationApiClient.class);
    private final CharacterPartService service = new CharacterPartService(sanitizer, repo, federation);

    private static VnCharacterPart storedPart(String svg) {
        return new VnCharacterPart("part-1", "alice", "default", "ear", svg, "PENDING",
                "protogen", Instant.now());
    }

    @Test
    void savePart_sanitizesStoresPending_andFilesHeldFinding() {
        String dirty = "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script>"
                + "<path class='region-fur' d='M0 0 L10 10 Z'/></svg>";
        when(repo.save(eq("alice"), eq("default"), eq("ear"), anyString(), eq("PENDING"), eq("protogen")))
                .thenAnswer(inv -> Mono.just(storedPart(inv.getArgument(3))));
        when(federation.fileFinding(any())).thenReturn(Mono.just(Map.of("status", "held")));

        VnCharacterPart out = service.savePart("alice", "default", "ear", "protogen", dirty).block();
        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo("PENDING");

        // the SANITIZED svg is what gets stored — the <script> is gone, the path survives.
        ArgumentCaptor<String> svg = ArgumentCaptor.forClass(String.class);
        verify(repo).save(eq("alice"), eq("default"), eq("ear"), svg.capture(), eq("PENDING"), eq("protogen"));
        assertThat(svg.getValue()).doesNotContainIgnoringCase("script").contains("region-fur");

        // ...and a held finding is filed: surface=character-part, disposition=flagged.
        ArgumentCaptor<FindingRequest> req = ArgumentCaptor.forClass(FindingRequest.class);
        verify(federation).fileFinding(req.capture());
        assertThat(req.getValue().surface()).isEqualTo("character-part");
        assertThat(req.getValue().disposition()).isEqualTo("flagged");
        assertThat(req.getValue().classification()).isNull();
        assertThat(req.getValue().confidence()).isNull();
        assertThat(req.getValue().policyHit()).isNull();
        assertThat(req.getValue().perceptualHash()).isNull();
    }

    @Test
    void savePart_malformedSvg_is422_nothingStored_noFinding() {
        StepVerifier.create(service.savePart("alice", "default", "ear", "protogen", "<svg><path d='M0 0'"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ApiException.class)
                        .hasMessageContaining("not a valid SVG"))
                .verify();
        verify(repo, never()).save(anyString(), any(), any(), anyString(), anyString(), any());
        verify(federation, never()).fileFinding(any());
    }

    @Test
    void savePart_nonSvgRoot_is422() {
        StepVerifier.create(service.savePart("alice", "default", null, null, "<html><body>hi</body></html>"))
                .expectError(ApiException.class)
                .verify();
        verify(repo, never()).save(anyString(), any(), any(), anyString(), anyString(), any());
    }

    @Test
    void savePart_blankSvg_is422() {
        StepVerifier.create(service.savePart("alice", "default", null, null, "   "))
                .expectError(ApiException.class)
                .verify();
        verify(repo, never()).save(anyString(), any(), any(), anyString(), anyString(), any());
    }

    @Test
    void savePart_federationOutage_doesNotFailSave_failSoft() {
        String dirty = "<svg xmlns='http://www.w3.org/2000/svg'><path d='M0 0 L1 1'/></svg>";
        when(repo.save(eq("alice"), eq("default"), any(), anyString(), eq("PENDING"), any()))
                .thenAnswer(inv -> Mono.just(storedPart(inv.getArgument(3))));
        // federation is unreachable — the finding-file errors, but the save must still succeed.
        when(federation.fileFinding(any()))
                .thenReturn(Mono.error(new RuntimeException("federation unreachable")));

        StepVerifier.create(service.savePart("alice", "default", null, null, dirty))
                .assertNext(p -> assertThat(p.status()).isEqualTo("PENDING"))
                .verifyComplete();
        // the part WAS stored despite the federation outage.
        verify(repo).save(eq("alice"), eq("default"), any(), anyString(), eq("PENDING"), any());
    }

    @Test
    void savePart_blankOwner_isRejected_nothingStored() {
        assertThatThrownBy(() ->
                service.savePart("  ", "default", null, null, "<svg xmlns='http://www.w3.org/2000/svg'/>"))
                .isInstanceOf(IllegalArgumentException.class);
        verify(repo, never()).save(anyString(), any(), any(), anyString(), anyString(), any());
    }

    @Test
    void savePart_nullOwner_isRejected() {
        assertThatThrownBy(() ->
                service.savePart(null, "default", null, null, "<svg xmlns='http://www.w3.org/2000/svg'/>"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void listMine_delegatesOwnerAndDomainScoped() {
        when(repo.listForOwner("alice", "default"))
                .thenReturn(reactor.core.publisher.Flux.just(storedPart("<svg/>")));
        assertThat(service.listMine("alice", "default").collectList().block()).hasSize(1);
        verify(repo).listForOwner("alice", "default");
    }

    @Test
    void getOwned_delegatesOwnerScopedLookup() {
        when(repo.findOwned("part-1", "alice")).thenReturn(Mono.just(storedPart("<svg/>")));
        assertThat(service.getOwned("part-1", "alice").block()).isNotNull();
        verify(repo).findOwned("part-1", "alice");
    }
}
