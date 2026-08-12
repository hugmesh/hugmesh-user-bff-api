package net.hugmesh.userbff.hsproxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Owner-scoped facade over {@link HsServiceTokenR2dbcRepository} + {@link HsTokenCipher}.
 * Encapsulates the at-rest crypto so callers (the broker + the proxy) only ever see the
 * DECRYPTED homeserver-native token in memory, never the stored ciphertext — and never a
 * cross-owner row (every method is keyed on the owner subject).
 *
 * <p>The custody upsert is update-first/insert-if-absent against the
 * {@code (owner_subject, platform)} unique constraint (a true upsert). The decrypted
 * token is NEVER returned to a client, NEVER logged.
 */
@Service
public class HsTokenCustody {

    private static final Logger log = LoggerFactory.getLogger(HsTokenCustody.class);

    private final HsServiceTokenR2dbcRepository repo;
    private final HsTokenCipher cipher;

    public HsTokenCustody(HsServiceTokenR2dbcRepository repo, HsTokenCipher cipher) {
        this.repo = repo;
        this.cipher = cipher;
    }

    /** Whether the at-rest cipher is configured (custody read/write requires it). */
    public boolean cipherAvailable() {
        return cipher.isAvailable();
    }

    /**
     * The decrypted homeserver-native access token for {@code ownerSubject} on
     * {@code platform}, or empty when there is no custody row OR the cipher cannot
     * decrypt (fail-closed — a tampered/unkeyed blob yields no token, never a throw).
     * Owner-scoped: another subject's row is structurally unreachable.
     */
    public Mono<String> loadAccessToken(String ownerSubject, String platform) {
        return repo.findByOwnerSubjectAndPlatform(ownerSubject, platform)
                .mapNotNull(row -> cipher.decrypt(row.accessTokenEnc()));
    }

    /** The full custody row for {@code ownerSubject}+{@code platform} (or empty). The
     *  encrypted token columns stay encrypted — the caller decrypts via the cipher. */
    public Mono<HsServiceTokenRow> findRow(String ownerSubject, String platform) {
        return repo.findByOwnerSubjectAndPlatform(ownerSubject, platform);
    }

    /**
     * Encrypt the freshly-minted homeserver-native tokens and UPSERT the owner's custody
     * row (update-first against the unique constraint; insert if absent). Returns the
     * upserted row's id. NEVER logs the token; the ciphertext is what lands in the DB.
     *
     * @throws IllegalStateException via the cipher if no key is configured (the proxy
     *                               checks {@link #cipherAvailable()} before minting)
     */
    public Mono<Void> upsert(String ownerSubject, String platform, String accessToken,
                             String refreshToken, Instant expiresAt, String localpart) {
        String accessEnc = cipher.encrypt(accessToken);
        String refreshEnc = (refreshToken == null || refreshToken.isBlank())
                ? null : cipher.encrypt(refreshToken);
        // Attempt an UPDATE first; if no rows were touched, INSERT instead.
        return repo.upsertUpdate(ownerSubject, platform, accessEnc, refreshEnc, expiresAt, localpart)
                .flatMap(updated -> insertIfAbsent(updated, ownerSubject, platform,
                        accessEnc, refreshEnc, expiresAt, localpart))
                .doOnSuccess(v -> log.debug("[hs-custody] upserted custody row owner={} platform={}",
                        ownerSubject, platform))
                .then();
    }

    /** If the UPDATE touched 0 rows the custody row is new — INSERT it, returning its generated id. */
    private Mono<Void> insertIfAbsent(Long updated, String ownerSubject, String platform,
                                      String accessEnc, String refreshEnc,
                                      java.time.Instant expiresAt, String localpart) {
        if (updated != null && updated > 0) {
            // Row already existed and was updated — nothing more to do.
            return Mono.empty();
        }
        // Fresh row: the id is DB-generated (changelog 015 column DEFAULT) — the
        // INSERT omits it and RETURNING id hands the generated UUID back, which we
        // consume (the upsert returns Void; cross-user isolation is the
        // owner-scoped (owner_subject, platform) predicate, unchanged).
        return repo.upsertInsertReturningId(ownerSubject, platform,
                accessEnc, refreshEnc, expiresAt, localpart).then();
    }

    /** Owner-scoped delete of the owner's custody row for a platform (used by tests /
     *  future revoke). Returns rows-deleted (0 = none for this owner). */
    public Mono<Long> delete(String ownerSubject, String platform) {
        return repo.deleteByOwnerSubjectAndPlatform(ownerSubject, platform);
    }
}
