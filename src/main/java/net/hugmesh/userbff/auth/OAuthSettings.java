package net.hugmesh.userbff.auth;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * What the Google/Discord sign-in (hugmesh-generator#1107) is allowed to do, read once at boot.
 * SHIPS DARK: {@code enabled=false} (the default) offers no provider anywhere.
 *
 * <ul>
 *   <li>A provider is CONFIGURED only when both its client id and its client secret are set
 *       (they are the same OAuth client the Casdoor provider of that name uses).</li>
 *   <li>Each domain lists the ways it offers to sign in ({@code domain-methods}, written by
 *       provisioning from the Studio's {@code signin_methods}): {@code mesh.example=password,
 *       google;shop.example=password}. A host is matched to the LONGEST domain it equals or
 *       ends in ({@code login.shop.example} -> {@code shop.example}). A host that matches no
 *       domain offers nothing: fail closed, never "every provider".</li>
 * </ul>
 */
public final class OAuthSettings {

    /** The sign-in method name that is not a provider here (the native login form). */
    static final String PASSWORD = "password";

    private final boolean enabled;
    private final Duration stateTtl;
    private final Map<OAuthProvider, Client> clients;
    private final Map<String, List<String>> domainMethods;

    /**
     * One provider's OAuth client (the secret never leaves this process). The three endpoint
     * overrides are blank in production (the provider's own constants apply); they exist so a
     * local stack can put a mock provider in place of Google or Discord for an end-to-end
     * walk, set at boot like the client, never from a request.
     */
    public record Client(String clientId, String clientSecret, String authorizeUrl,
                         String tokenUrl, String userinfoUrl) {
        public Client(String clientId, String clientSecret) {
            this(clientId, clientSecret, "", "", "");
        }

        public String authorize(OAuthProvider p) {
            return blank(authorizeUrl) ? p.authorizeUrl() : authorizeUrl.trim();
        }

        public String token(OAuthProvider p) {
            return blank(tokenUrl) ? p.tokenUrl() : tokenUrl.trim();
        }

        public String userinfo(OAuthProvider p) {
            return blank(userinfoUrl) ? p.userinfoUrl() : userinfoUrl.trim();
        }

        private static boolean blank(String s) {
            return s == null || s.isBlank();
        }

        public boolean configured() {
            return clientId != null && !clientId.isBlank()
                    && clientSecret != null && !clientSecret.isBlank();
        }

        @Override
        public String toString() {
            return "Client[clientId=" + clientId + ", clientSecret=<redacted>]";
        }
    }

    public OAuthSettings(boolean enabled, Duration stateTtl, Map<OAuthProvider, Client> clients,
                         String domainMethods) {
        this.enabled = enabled;
        this.stateTtl = stateTtl == null || stateTtl.isNegative() || stateTtl.isZero()
                ? Duration.ofMinutes(10) : stateTtl;
        Map<OAuthProvider, Client> copy = new EnumMap<>(OAuthProvider.class);
        if (clients != null) {
            copy.putAll(clients);
        }
        this.clients = Collections.unmodifiableMap(copy);
        this.domainMethods = parseDomainMethods(domainMethods);
    }

    public boolean enabled() {
        return enabled;
    }

    public Duration stateTtl() {
        return stateTtl;
    }

    public Optional<Client> client(OAuthProvider provider) {
        Client c = clients.get(provider);
        return c != null && c.configured() ? Optional.of(c) : Optional.empty();
    }

    /** The domain a request host belongs to (the longest configured match), if any. */
    public Optional<String> domainFor(String host) {
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }
        String h = host.trim().toLowerCase(Locale.ROOT);
        int colon = h.lastIndexOf(':');
        if (colon > 0 && h.indexOf(']') < colon) {
            h = h.substring(0, colon);                  // the domain match ignores the port
        }
        String best = null;
        for (String d : domainMethods.keySet()) {
            if ((h.equals(d) || h.endsWith("." + d)) && (best == null || d.length() > best.length())) {
                best = d;
            }
        }
        return Optional.ofNullable(best);
    }

    /**
     * The providers a request on {@code host} may use: enabled, configured, and listed for the
     * host's domain. Empty when dark, when the host matches no domain, or when the domain lists
     * none — in that order of precedence, never a default "all".
     */
    public List<OAuthProvider> providersFor(String host) {
        if (!enabled) {
            return List.of();
        }
        Optional<String> domain = domainFor(host);
        if (domain.isEmpty()) {
            return List.of();
        }
        List<String> methods = domainMethods.get(domain.get());
        List<OAuthProvider> out = new ArrayList<>();
        for (OAuthProvider p : OAuthProvider.values()) {
            if (methods.contains(p.id()) && client(p).isPresent()) {
                out.add(p);
            }
        }
        return out;
    }

    /**
     * Whether {@code POST /bff/login} must refuse a password on {@code host}: only while the
     * sign-in settings are live and the host's domain lists its ways WITHOUT {@code password}.
     * Dark, or a host that matches no listed domain, keeps today's password sign-in.
     */
    public boolean passwordRefused(String host) {
        if (!enabled) {
            return false;
        }
        Optional<String> domain = domainFor(host);
        return domain.isPresent() && !domainMethods.get(domain.get()).contains(PASSWORD);
    }

    public boolean allows(String host, OAuthProvider provider) {
        return providersFor(host).contains(provider);
    }

    /**
     * {@code a.example=password,google;b.example=password} -> ordered map. Blank or malformed
     * entries are dropped (each entry must name a domain and at least one method); names are
     * lowercased. Unknown method names are kept but never match a provider.
     */
    static Map<String, List<String>> parseDomainMethods(String spec) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (spec == null) {
            return out;
        }
        for (String entry : spec.split(";")) {
            int eq = entry.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String domain = entry.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            List<String> methods = new ArrayList<>();
            for (String m : entry.substring(eq + 1).split(",")) {
                String t = m.trim().toLowerCase(Locale.ROOT);
                if (!t.isEmpty() && !methods.contains(t)) {
                    methods.add(t);
                }
            }
            if (!domain.isEmpty() && !methods.isEmpty()) {
                out.put(domain, List.copyOf(methods));
            }
        }
        return out;
    }
}
