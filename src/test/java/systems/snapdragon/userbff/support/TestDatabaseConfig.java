package systems.snapdragon.userbff.support;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import liquibase.integration.spring.SpringLiquibase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.r2dbc.core.DatabaseClient;

import javax.sql.DataSource;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared test database wiring: a single H2 in-memory database that Liquibase applies
 * the production changelog over (via a JDBC datasource — Liquibase has no R2DBC
 * runner) AND that the runtime {@link DatabaseClient} accesses reactively via R2DBC.
 * The JDBC URL {@code jdbc:h2:mem:<name>} and the R2DBC URL
 * {@code r2dbc:h2:mem:///<name>} resolve to the SAME H2 mem store, so the R2DBC
 * repositories run against the real Liquibase-applied schema. Copied from the
 * admin-bff / federation-api TestDatabaseConfig pattern.
 *
 * <p>Each test class gets a UNIQUE db name so classes don't share rows. H2 runs in
 * PostgreSQL compatibility mode with NON_KEYWORDS for any reserved column names so
 * the same Liquibase DDL + production SQL run here exactly as on Postgres.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestDatabaseConfig {

    private static final AtomicInteger DB_SEQ = new AtomicInteger();

    /** A fresh per-context db name keeps test classes isolated. */
    private final String dbName = "userbff_test_" + DB_SEQ.incrementAndGet();

    private static final String H2_OPTS =
            ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL;NON_KEYWORDS=USER,VALUE;DATABASE_TO_LOWER=TRUE";

    /**
     * The JDBC (Liquibase) connection opens the H2 mem store first as user {@code sa},
     * which fixes the store's credentials. The r2dbc-h2 driver sends no username by
     * default, so pin the same {@code sa}/empty credentials on the R2DBC URL so both
     * handles share the store.
     */
    private static final String R2DBC_OPTS = H2_OPTS + ";USER=sa;PASSWORD=";

    @Bean
    public DataSource liquibaseDataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.h2.Driver");
        ds.setUrl("jdbc:h2:mem:" + dbName + H2_OPTS);
        ds.setUsername("sa");
        ds.setPassword("");
        return ds;
    }

    /** Apply the production changelog over the shared H2 (runs before the
     *  DatabaseClient is used; @TestConfiguration beans init eagerly). */
    @Bean
    public SpringLiquibase liquibase(DataSource liquibaseDataSource) {
        SpringLiquibase lb = new SpringLiquibase();
        lb.setDataSource(liquibaseDataSource);
        lb.setChangeLog("classpath:db/changelog/db.changelog-master.xml");
        return lb;
    }

    @Bean
    public ConnectionFactory connectionFactory() {
        return ConnectionFactories.get("r2dbc:h2:mem:///" + dbName + R2DBC_OPTS);
    }

    /** The reactive client the repositories use — depends on the Liquibase bean so
     *  the schema is applied before any query runs. */
    @Bean
    public DatabaseClient databaseClient(ConnectionFactory connectionFactory, SpringLiquibase liquibase) {
        return DatabaseClient.create(connectionFactory);
    }
}
