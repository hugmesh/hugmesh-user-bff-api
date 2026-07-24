package systems.hugmesh.userbff.character;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.userbff.auth.AdminBffInternalClient;
import systems.hugmesh.userbff.auth.CanonicalIdentityResolver;
import systems.hugmesh.userbff.hsproxy.HsServiceTokenRow;
import systems.hugmesh.userbff.hsproxy.HsTokenCustody;
import systems.hugmesh.userbff.hsproxy.MintedToken;
import systems.hugmesh.userbff.hsproxy.ServiceTokenBroker;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for {@link StickerPackRegistrationService} -- the SERVER (write-side) half of the
 * MSC2545 sticker-pack feature -- with EVERYTHING mocked (no DB, no homeserver). Proves:
 * <ul>
 *   <li>DARK-BY-DEFAULT: the flag OFF short-circuits to a no-op -- ZERO cipher/custody/Matrix
 *       calls (the feature ships inert in dev + CI);</li>
 *   <li>cipher unavailable =&gt; no-op (nothing to authorise with);</li>
 *   <li>HAPPY PATH (custody token present): GET -&gt; MERGE -&gt; PUT, the merged pack PRESERVING a
 *       pre-existing NON-VN emote and de-duping VN expressions newest-first;</li>
 *   <li>MINT-ON-EMPTY: an empty custody token re-mints once, then registers;</li>
 *   <li>CANONICAL-LOCALPART MINT (no custody row): the first-ever mint resolves the owner's OWN
 *       {@code casdoor:} account localpart via {@link CanonicalIdentityResolver} and FAILS CLOSED
 *       (no mint) when it cannot -- never the old raw-subject derivation;</li>
 *   <li>FAIL-SOFT: any downstream error is swallowed (completes empty, never throws).</li>
 * </ul>
 * The static {@link StickerPackRegistrationService#mergePack} is unit-tested directly.
 */
class StickerPackRegistrationServiceTest {

    private static final String OWNER = "alice-sub";
    /** The owner's OWN account key (subject has no ':' -> normalised to casdoor:<subject>). */
    private static final String OWNER_ACCOUNT_ID = "casdoor:alice-sub";
    private static final String LOCALPART = "alice";
    private static final String USER_ID = "@alice:hs.test";
    private static final String SERVER = "hs.test";
    private static final String TOKEN = "syt_live_token";

    private final VnStickerRepository stickerRepo = mock(VnStickerRepository.class);
    private final HsTokenCustody custody = mock(HsTokenCustody.class);
    private final ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
    private final MatrixClientApiClient matrix = mock(MatrixClientApiClient.class);
    private final AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);

    /** Build the service with the dark flag set as requested (real resolver over the mock). */
    private StickerPackRegistrationService service(boolean enabled) {
        return new StickerPackRegistrationService(stickerRepo, custody, broker, matrix,
                new CanonicalIdentityResolver(adminBff), enabled, SERVER);
    }

    private static VnSticker sticker(String id, String expr, String mxc, Instant created) {
        return new VnSticker(id, OWNER, "default", expr, mxc, "ACTIVE", 1L, created);
    }

    private static HsServiceTokenRow custodyRow() {
        return new HsServiceTokenRow("row-1", OWNER, HsServiceTokenRow.PLATFORM_MATRIX,
                "enc", null, null, LOCALPART, Instant.now());
    }

    private static AdminBffInternalClient.AccountView account(String localpart) {
        return new AdminBffInternalClient.AccountView(OWNER_ACCOUNT_ID, "casdoor", OWNER, true,
                List.of("user"), localpart);
    }

    // -- DARK-BY-DEFAULT (flag OFF) --------------------------------------------------------

    @Test
    void flagOff_isNoOp_zeroMatrixCalls() {
        StepVerifier.create(service(false).registerActivePack(OWNER)).verifyComplete();

        // Nothing downstream is touched -- the short-circuit is BEFORE cipher/custody/matrix.
        verify(custody, never()).cipherAvailable();
        verify(custody, never()).findRow(anyString(), anyString());
        verify(matrix, never()).getAccountData(any(), any(), any());
        verify(matrix, never()).setAccountData(any(), any(), any(), any());
    }

    @Test
    void blankOwner_isNoOp_evenWhenEnabled() {
        StepVerifier.create(service(true).registerActivePack("  ")).verifyComplete();
        verify(custody, never()).cipherAvailable();
    }

    // -- cipher unavailable ----------------------------------------------------------------

    @Test
    void cipherUnavailable_isNoOp_noCustodyOrMatrix() {
        when(custody.cipherAvailable()).thenReturn(false);

        StepVerifier.create(service(true).registerActivePack(OWNER)).verifyComplete();

        verify(custody, never()).findRow(anyString(), anyString());
        verify(matrix, never()).setAccountData(any(), any(), any(), any());
    }

    // -- HAPPY PATH (token present) --------------------------------------------------------

    @Test
    void happyPath_loadedToken_getMergePut_preservesNonVnEmote() {
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.findRow(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.just(custodyRow()));
        when(custody.loadAccessToken(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.just(TOKEN));

        Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
        // newest-first: the FIRST "happy" (newer mxc) must win the de-dup.
        when(stickerRepo.listActiveForOwner(OWNER)).thenReturn(Flux.just(
                sticker("s1", "happy", "mxc://h/happy-new", t0.plusSeconds(10)),
                sticker("s2", "sad", "mxc://h/sad", t0.plusSeconds(5)),
                sticker("s3", "happy", "mxc://h/happy-old", t0)));

        // A pre-existing NON-VN emote already in the user's account-data must survive.
        Map<String, Object> existingImages = new LinkedHashMap<>();
        existingImages.put("party_blob", Map.of("url", "mxc://h/blob", "body", "party_blob"));
        Map<String, Object> existing = new LinkedHashMap<>();
        existing.put("images", existingImages);
        when(matrix.getAccountData(USER_ID, StickerPackRegistrationService.EMOTES_TYPE, TOKEN))
                .thenReturn(Mono.just(existing));

        ArgumentCaptor<Map<String, Object>> body = mapCaptor();
        when(matrix.setAccountData(eq(USER_ID), eq(StickerPackRegistrationService.EMOTES_TYPE),
                body.capture(), eq(TOKEN))).thenReturn(Mono.empty());

        StepVerifier.create(service(true).registerActivePack(OWNER)).verifyComplete();

        Map<String, Object> written = body.getValue();
        @SuppressWarnings("unchecked")
        Map<String, Object> images = (Map<String, Object>) written.get("images");
        // pre-existing non-VN emote preserved
        assertThat(images).containsKey("party_blob");
        // both VN expressions placed; "happy" de-duped to the NEWEST mxc
        assertThat(images).containsKeys("happy", "sad");
        @SuppressWarnings("unchecked")
        Map<String, Object> happy = (Map<String, Object>) images.get("happy");
        assertThat(happy.get("url")).isEqualTo("mxc://h/happy-new");
        // pack block present with sticker usage
        @SuppressWarnings("unchecked")
        Map<String, Object> pack = (Map<String, Object>) written.get("pack");
        assertThat(pack.get("usage")).isEqualTo(List.of("sticker"));
    }

    // -- MINT-ON-EMPTY-TOKEN ---------------------------------------------------------------

    @Test
    void emptyToken_reMintsOnce_thenRegisters() {
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.findRow(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.just(custodyRow()));
        // loaded token is empty -> re-mint path supplies one
        when(custody.loadAccessToken(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.empty());
        when(broker.mintMatrix(OWNER, LOCALPART))
                .thenReturn(Mono.just(new MintedToken("syt_minted", null, null, LOCALPART)));
        when(stickerRepo.listActiveForOwner(OWNER)).thenReturn(Flux.empty());
        when(matrix.getAccountData(any(), any(), eq("syt_minted"))).thenReturn(Mono.empty());
        when(matrix.setAccountData(any(), any(), any(), eq("syt_minted"))).thenReturn(Mono.empty());

        StepVerifier.create(service(true).registerActivePack(OWNER)).verifyComplete();

        verify(broker).mintMatrix(OWNER, LOCALPART);
        verify(matrix).setAccountData(any(), any(), any(), eq("syt_minted"));
    }

    // -- canonical-localpart mint (account-takeover-by-collision fix, sticker leg) ----------

    @Test
    void noCustodyRow_resolvesCanonicalLocalpart_mintsCreatesRow_thenRegisters() {
        when(custody.cipherAvailable()).thenReturn(true);
        // No custody row at all -> mintThenRegister resolves the owner's OWN casdoor account.
        when(custody.findRow(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.empty());
        when(adminBff.getAccount(OWNER_ACCOUNT_ID)).thenReturn(Mono.just(account(LOCALPART)));
        when(broker.mintMatrix(eq(OWNER), eq(LOCALPART)))
                .thenReturn(Mono.just(new MintedToken("syt_fresh", null, null, LOCALPART)));
        when(stickerRepo.listActiveForOwner(OWNER)).thenReturn(Flux.empty());
        when(matrix.getAccountData(any(), any(), eq("syt_fresh"))).thenReturn(Mono.empty());
        when(matrix.setAccountData(any(), any(), any(), eq("syt_fresh"))).thenReturn(Mono.empty());

        StepVerifier.create(service(true).registerActivePack(OWNER)).verifyComplete();

        verify(adminBff).getAccount(OWNER_ACCOUNT_ID);
        verify(broker).mintMatrix(eq(OWNER), eq(LOCALPART));
        verify(matrix).setAccountData(any(), any(), any(), eq("syt_fresh"));
    }

    @Test
    void mintThenRegister_prefersCanonicalPersistedLocalpart_overRawSubjectDerivation() {
        // The custody-row path already mints under the PERSISTED row.localpart() for a returning
        // owner. mintThenRegister (first-ever mint) must mint under the SAME kind of canonical
        // value from the owner's OWN casdoor account -- not a sanitized derivation of the raw
        // ownerSubject -- proving parity between the two mint paths.
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.findRow(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.empty());
        when(adminBff.getAccount(OWNER_ACCOUNT_ID)).thenReturn(Mono.just(account("alice-canonical")));
        when(broker.mintMatrix(eq(OWNER), eq("alice-canonical")))
                .thenReturn(Mono.just(new MintedToken("syt_canonical", null, null, "alice-canonical")));
        when(stickerRepo.listActiveForOwner(OWNER)).thenReturn(Flux.empty());
        when(matrix.getAccountData(any(), any(), eq("syt_canonical"))).thenReturn(Mono.empty());
        when(matrix.setAccountData(any(), any(), any(), eq("syt_canonical"))).thenReturn(Mono.empty());

        StepVerifier.create(service(true).registerActivePack(OWNER)).verifyComplete();

        verify(broker).mintMatrix(eq(OWNER), eq("alice-canonical"));
        // The OLD (pre-fix) behaviour would have minted under the raw-subject derivation --
        // must never happen once admin-bff resolves a canonical value.
        verify(broker, never()).mintMatrix(eq(OWNER), eq(ServiceTokenBroker.localpart(OWNER)));
    }

    @Test
    void mintThenRegister_adminBffUnresolvable_failsClosed_noMint_neverRawDerivation() {
        // admin-bff errors (unreachable / disabled) -> FAIL CLOSED: no candidate resolves, so the
        // sticker pack is simply NOT registered (a no-op). The class stays fail-soft overall (the
        // moderator's activation is never failed), but the OLD raw-subject fallback -- the exact
        // takeover vector on this leg -- is GONE: NOTHING is minted.
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.findRow(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.empty());
        when(adminBff.getAccount(OWNER_ACCOUNT_ID)).thenReturn(Mono.error(new IllegalStateException("admin-bff disabled")));

        StepVerifier.create(service(true).registerActivePack(OWNER)).verifyComplete();

        verify(broker, never()).mintMatrix(anyString(), anyString());
        verify(matrix, never()).setAccountData(any(), any(), any(), any());
    }

    @Test
    void mintThenRegister_noCanonicalAccount_failsClosed_noMint() {
        // The owner's own casdoor account has no persisted localpart (blank) -> no candidate ->
        // no mint. Never the raw-subject derivation.
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.findRow(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.empty());
        when(adminBff.getAccount(OWNER_ACCOUNT_ID)).thenReturn(Mono.just(account("")));

        StepVerifier.create(service(true).registerActivePack(OWNER)).verifyComplete();

        verify(broker, never()).mintMatrix(anyString(), anyString());
        verify(matrix, never()).setAccountData(any(), any(), any(), any());
    }

    // -- FAIL-SOFT -------------------------------------------------------------------------

    @Test
    void downstreamError_isSwallowed_completesEmpty() {
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.findRow(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.just(custodyRow()));
        when(custody.loadAccessToken(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.just(TOKEN));
        when(stickerRepo.listActiveForOwner(OWNER)).thenReturn(Flux.empty());
        when(matrix.getAccountData(any(), any(), any())).thenReturn(Mono.just(new LinkedHashMap<>()));
        // the PUT blows up -- the service must SWALLOW it (no throw, completes empty).
        when(matrix.setAccountData(any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("homeserver down")));

        StepVerifier.create(service(true).registerActivePack(OWNER)).verifyComplete();
    }

    @Test
    void blankMintedToken_isNoOp_noMatrixWrite() {
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.findRow(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.just(custodyRow()));
        // load empty -> mint returns a BLANK token -> registerWith short-circuits (no write).
        when(custody.loadAccessToken(OWNER, HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.empty());
        when(broker.mintMatrix(OWNER, LOCALPART))
                .thenReturn(Mono.just(new MintedToken("   ", null, null, LOCALPART)));

        StepVerifier.create(service(true).registerActivePack(OWNER)).verifyComplete();

        verify(matrix, never()).setAccountData(any(), any(), any(), any());
    }

    // -- mergePack (static -- direct unit test) --------------------------------------------

    @Test
    void mergePack_preservesNonVn_overwritesStaleSameKey_skipsMalformed_dedupsNewestFirst() {
        // existing account-data: a non-VN emote + a STALE "happy" we will overwrite.
        Map<String, Object> existingImages = new LinkedHashMap<>();
        existingImages.put("party_blob", Map.of("url", "mxc://h/blob", "body", "party_blob"));
        existingImages.put("happy", Map.of("url", "mxc://h/STALE", "body", "happy"));
        Map<String, Object> existing = new LinkedHashMap<>();
        existing.put("images", existingImages);
        existing.put("pack", new LinkedHashMap<>(Map.of("custom_meta", "keep-me")));

        Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
        List<VnSticker> active = List.of(
                sticker("s1", "happy", "mxc://h/happy-new", t0.plusSeconds(10)), // newest happy wins
                sticker("sX", "  ", "mxc://h/whatever", t0.plusSeconds(8)),       // blank expr -> skip
                sticker("sY", "blank_mxc", null, t0.plusSeconds(7)),             // null mxc -> skip
                sticker("s3", "happy", "mxc://h/happy-old", t0.plusSeconds(1)),  // older happy -> skip (de-dup)
                sticker("s4", "sad", "mxc://h/sad", t0));

        Map<String, Object> merged = StickerPackRegistrationService.mergePack(OWNER, existing, active);

        @SuppressWarnings("unchecked")
        Map<String, Object> images = (Map<String, Object>) merged.get("images");
        // non-VN preserved
        assertThat(images).containsKey("party_blob");
        // malformed rows skipped
        assertThat(images).doesNotContainKey("blank_mxc");
        assertThat(images).doesNotContainKeys("  ", "");
        // stale "happy" overwritten with the NEWEST mxc (de-dup keeps newest-first)
        @SuppressWarnings("unchecked")
        Map<String, Object> happy = (Map<String, Object>) images.get("happy");
        assertThat(happy.get("url")).isEqualTo("mxc://h/happy-new");
        assertThat(happy.get("body")).isEqualTo("happy");
        assertThat(happy.get("usage")).isEqualTo(List.of("sticker"));
        // sad placed
        assertThat(images).containsKey("sad");

        // pack: custom metadata preserved + display_name + sticker usage set
        @SuppressWarnings("unchecked")
        Map<String, Object> pack = (Map<String, Object>) merged.get("pack");
        assertThat(pack.get("custom_meta")).isEqualTo("keep-me");
        assertThat(pack.get("usage")).isEqualTo(List.of("sticker"));
        assertThat(pack).containsKey("display_name");
    }

    @Test
    void mergePack_nullExisting_startsFresh() {
        Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
        Map<String, Object> merged = StickerPackRegistrationService.mergePack(
                OWNER, null, List.of(sticker("s1", "happy", "mxc://h/1", t0)));

        @SuppressWarnings("unchecked")
        Map<String, Object> images = (Map<String, Object>) merged.get("images");
        assertThat(images).containsOnlyKeys("happy");
        assertThat(merged).containsKey("pack");
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<Map<String, Object>> mapCaptor() {
        return ArgumentCaptor.forClass(Map.class);
    }
}
