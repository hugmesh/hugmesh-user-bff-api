package systems.hugmesh.userbff.config;

import io.r2dbc.spi.ConnectionFactory;
import org.springframework.boot.data.r2dbc.autoconfigure.DataR2dbcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.r2dbc.convert.R2dbcCustomConversions;
import org.springframework.data.r2dbc.dialect.DialectResolver;
import org.springframework.data.r2dbc.dialect.R2dbcDialect;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/**
 * R2DBC type-conversion shims. Copied from the federation-api / games
 * {@code R2dbcConvertersConfig}: the Postgres driver returns {@code OffsetDateTime}
 * / {@code LocalDateTime} for {@code timestamptz} / {@code timestamp} columns while
 * the entities expect {@code Instant}. Spring Data's reflective JSR-310 fallbacks
 * are skipped under GraalVM native-image, so registering the two reading converters
 * explicitly makes the conversion deterministic in both JVM and native modes (and
 * on the H2 slice-test DB, which also hands back {@code LocalDateTime} for
 * {@code timestamp}).
 */
@Configuration(proxyBeanMethods = false)
public class R2dbcConvertersConfig {

    /** Replaces the auto-configured {@link R2dbcCustomConversions} bean
     *  (see {@link DataR2dbcAutoConfiguration}) with the two timestamp converters
     *  added on top of the dialect defaults. */
    @Bean
    public R2dbcCustomConversions r2dbcCustomConversions(ConnectionFactory connectionFactory) {
        R2dbcDialect dialect = DialectResolver.getDialect(connectionFactory);
        List<Object> converters = new ArrayList<>(dialect.getConverters());
        converters.add(new OffsetDateTimeToInstantConverter());
        converters.add(new LocalDateTimeToInstantConverter());
        return R2dbcCustomConversions.of(dialect, converters);
    }

    @ReadingConverter
    static class OffsetDateTimeToInstantConverter implements Converter<OffsetDateTime, Instant> {
        @Override public Instant convert(OffsetDateTime source) { return source.toInstant(); }
    }

    @ReadingConverter
    static class LocalDateTimeToInstantConverter implements Converter<LocalDateTime, Instant> {
        @Override public Instant convert(LocalDateTime source) { return source.toInstant(ZoneOffset.UTC); }
    }
}
