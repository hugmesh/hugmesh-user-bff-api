package systems.snapdragon.userbff.character;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.commons.web.ApiException;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for {@link CharacterModerationService} — the RECEIVING half of the
 * part/sticker activation loop — with mocked {@link VnCharacterPartRepository} +
 * {@link VnStickerRepository}. Proves the PENDING-guarded flip and its idempotency:
 * <ul>
 *   <li>a 1-row flip re-reads and returns the post-flip row (ACTIVE / REJECTED);</li>
 *   <li>a 0-row update (unknown id, or an already-resolved / non-PENDING row) is a no-op:
 *       EMPTY is returned and the row is NEVER re-read (the receiver maps EMPTY to a 404);</li>
 *   <li>an invalid target status (not ACTIVE/REJECTED) is a 400 BEFORE any DB write;</li>
 *   <li>both surfaces (part + sticker) behave identically;</li>
 *   <li>MSC2545 HOOK: a SUCCESSFUL sticker→ACTIVE flip invokes the pack registrar; a
 *       REJECTED flip and a no-op flip do NOT; a registration error never fails the flip.</li>
 * </ul>
 */
class CharacterModerationServiceTest {

    private final VnCharacterPartRepository partRepo = mock(VnCharacterPartRepository.class);
    private final VnStickerRepository stickerRepo = mock(VnStickerRepository.class);
    private final StickerPackRegistrationService packRegistration =
            mock(StickerPackRegistrationService.class);
    private final CharacterModerationService service =
            new CharacterModerationService(partRepo, stickerRepo, packRegistration);

    {
        // Default: the registrar is a no-op success (the dark-by-default contract). Lenient so
        // the non-hook tests (parts / rejected / no-op) don't trip Mockito's strict stubbing.
        lenient().when(packRegistration.registerActivePack(anyString())).thenReturn(Mono.empty());
    }

    private static VnCharacterPart part(String id, String status) {
        return new VnCharacterPart(id, "alice", "default", "ear", "<svg/>", status, "protogen", 7L, Instant.now());
    }

    private static VnSticker sticker(String id, String status) {
        return new VnSticker(id, "alice", "default", "happy", "mxc://h/1", status, 9L, Instant.now());
    }

    // ── PART ────────────────────────────────────────────────────────────────

    @Test
    void resolvePart_pending_flipsToActive_andReturnsPostFlipRow() {
        when(partRepo.updateStatusByIdWherePending("p1", "ACTIVE")).thenReturn(Mono.just(1));
        when(partRepo.findAnyById("p1")).thenReturn(Mono.just(part("p1", "ACTIVE")));

        StepVerifier.create(service.resolvePart("p1", "ACTIVE", 7L, "mod-bob"))
                .assertNext(p -> assertThat(p.status()).isEqualTo("ACTIVE"))
                .verifyComplete();

        verify(partRepo).updateStatusByIdWherePending("p1", "ACTIVE");
        verify(partRepo).findAnyById("p1");
    }

    @Test
    void resolvePart_pending_flipsToRejected() {
        when(partRepo.updateStatusByIdWherePending("p2", "REJECTED")).thenReturn(Mono.just(1));
        when(partRepo.findAnyById("p2")).thenReturn(Mono.just(part("p2", "REJECTED")));

        StepVerifier.create(service.resolvePart("p2", "REJECTED", 8L, "mod-bob"))
                .assertNext(p -> assertThat(p.status()).isEqualTo("REJECTED"))
                .verifyComplete();
    }

    @Test
    void resolvePart_notPending_isNoOp_empty_neverReReads() {
        // 0 rows: already-resolved or unknown id. Idempotent no-op -> EMPTY, no re-read.
        when(partRepo.updateStatusByIdWherePending("p3", "ACTIVE")).thenReturn(Mono.just(0));

        StepVerifier.create(service.resolvePart("p3", "ACTIVE", 7L, "mod-bob"))
                .verifyComplete();   // empty

        verify(partRepo).updateStatusByIdWherePending("p3", "ACTIVE");
        verify(partRepo, never()).findAnyById(anyString());
    }

    @Test
    void resolvePart_secondResolve_isIdempotentNoOp() {
        // first resolve flips (1 row); the SAME finding resolved again flips 0 rows.
        when(partRepo.updateStatusByIdWherePending("p4", "REJECTED"))
                .thenReturn(Mono.just(1))
                .thenReturn(Mono.just(0));
        when(partRepo.findAnyById("p4")).thenReturn(Mono.just(part("p4", "REJECTED")));

        StepVerifier.create(service.resolvePart("p4", "REJECTED", 1L, "mod")).expectNextCount(1).verifyComplete();
        StepVerifier.create(service.resolvePart("p4", "REJECTED", 1L, "mod")).verifyComplete();  // no-op
    }

    @Test
    void resolvePart_invalidStatus_is400_nothingWritten() {
        StepVerifier.create(service.resolvePart("p5", "PENDING", 7L, "mod"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ApiException.class)
                        .hasMessageContaining("status must be one of"))
                .verify();
        StepVerifier.create(service.resolvePart("p5", "banana", 7L, "mod"))
                .expectError(ApiException.class)
                .verify();
        StepVerifier.create(service.resolvePart("p5", null, 7L, "mod"))
                .expectError(ApiException.class)
                .verify();

        verify(partRepo, never()).updateStatusByIdWherePending(anyString(), anyString());
    }

    // ── STICKER ─────────────────────────────────────────────────────────────

    @Test
    void resolveSticker_pending_flipsToActive_andReturnsPostFlipRow() {
        when(stickerRepo.updateStatusByIdWherePending("s1", "ACTIVE")).thenReturn(Mono.just(1));
        when(stickerRepo.findAnyById("s1")).thenReturn(Mono.just(sticker("s1", "ACTIVE")));

        StepVerifier.create(service.resolveSticker("s1", "ACTIVE", 9L, "mod-bob"))
                .assertNext(s -> assertThat(s.status()).isEqualTo("ACTIVE"))
                .verifyComplete();

        verify(stickerRepo).updateStatusByIdWherePending("s1", "ACTIVE");
        verify(stickerRepo).findAnyById("s1");
    }

    @Test
    void resolveSticker_notPending_isNoOp_empty_neverReReads() {
        when(stickerRepo.updateStatusByIdWherePending("s2", "REJECTED")).thenReturn(Mono.just(0));

        StepVerifier.create(service.resolveSticker("s2", "REJECTED", 9L, "mod-bob"))
                .verifyComplete();

        verify(stickerRepo, never()).findAnyById(anyString());
    }

    @Test
    void resolveSticker_invalidStatus_is400_nothingWritten() {
        StepVerifier.create(service.resolveSticker("s3", "ACTIVATED", 9L, "mod"))
                .expectError(ApiException.class)
                .verify();
        verify(stickerRepo, never()).updateStatusByIdWherePending(anyString(), anyString());
    }

    // ── MSC2545 PACK-REGISTRATION HOOK ────────────────────────────────────────

    @Test
    void resolveSticker_activeFlip_invokesPackRegistration_withOwnerSubject() {
        when(stickerRepo.updateStatusByIdWherePending("s10", "ACTIVE")).thenReturn(Mono.just(1));
        when(stickerRepo.findAnyById("s10")).thenReturn(Mono.just(sticker("s10", "ACTIVE")));

        StepVerifier.create(service.resolveSticker("s10", "ACTIVE", 9L, "mod-bob"))
                .assertNext(s -> assertThat(s.status()).isEqualTo("ACTIVE"))
                .verifyComplete();

        // the hook fires with the OWNER SUBJECT off the post-flip row (alice).
        verify(packRegistration).registerActivePack("alice");
    }

    @Test
    void resolveSticker_rejectedFlip_doesNotRegister() {
        when(stickerRepo.updateStatusByIdWherePending("s11", "REJECTED")).thenReturn(Mono.just(1));
        when(stickerRepo.findAnyById("s11")).thenReturn(Mono.just(sticker("s11", "REJECTED")));

        StepVerifier.create(service.resolveSticker("s11", "REJECTED", 9L, "mod-bob"))
                .assertNext(s -> assertThat(s.status()).isEqualTo("REJECTED"))
                .verifyComplete();

        // REJECTED is NOT an activation — the pack must never be touched.
        verify(packRegistration, never()).registerActivePack(anyString());
    }

    @Test
    void resolveSticker_noOpFlip_doesNotRegister() {
        // 0 rows (unknown / already-resolved) → EMPTY → the hook never runs.
        when(stickerRepo.updateStatusByIdWherePending("s12", "ACTIVE")).thenReturn(Mono.just(0));

        StepVerifier.create(service.resolveSticker("s12", "ACTIVE", 9L, "mod-bob"))
                .verifyComplete();

        verify(stickerRepo, never()).findAnyById(anyString());
        verify(packRegistration, never()).registerActivePack(anyString());
    }

    @Test
    void resolveSticker_registrationError_doesNotFailTheFlip() {
        when(stickerRepo.updateStatusByIdWherePending("s13", "ACTIVE")).thenReturn(Mono.just(1));
        when(stickerRepo.findAnyById("s13")).thenReturn(Mono.just(sticker("s13", "ACTIVE")));
        // the registrar BLOWS UP — the moderator's flip must still succeed (fail-soft).
        when(packRegistration.registerActivePack("alice"))
                .thenReturn(Mono.error(new RuntimeException("homeserver down")));

        StepVerifier.create(service.resolveSticker("s13", "ACTIVE", 9L, "mod-bob"))
                .assertNext(s -> assertThat(s.status()).isEqualTo("ACTIVE"))
                .verifyComplete();

        verify(packRegistration).registerActivePack("alice");
    }

    @Test
    void resolvePart_activeFlip_neverRegisters_partsHaveNoPack() {
        when(partRepo.updateStatusByIdWherePending("p10", "ACTIVE")).thenReturn(Mono.just(1));
        when(partRepo.findAnyById("p10")).thenReturn(Mono.just(part("p10", "ACTIVE")));

        StepVerifier.create(service.resolvePart("p10", "ACTIVE", 7L, "mod-bob"))
                .expectNextCount(1).verifyComplete();

        // parts have no MSC2545 pack — the registrar is for stickers only.
        verify(packRegistration, never()).registerActivePack(anyString());
    }
}
