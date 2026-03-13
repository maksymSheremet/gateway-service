package my.code.gateway.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import my.code.gateway.config.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtValidationFilterTest {

    private static final String TEST_SECRET = "dGVzdC1zZWNyZXQta2V5LWZvci1obWFjLXNoYTM4NC1hbGdvcml0aG0tMTIz";
    private static final String ISSUER = "auth-service";

    private JwtValidationFilter filter;
    private GatewayFilterChain chain;
    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties(TEST_SECRET);
        filter = new JwtValidationFilter(properties);

        chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
    }

    @Test
    @DisplayName("getOrder() returns -1 - filter executes before routing")
    void getOrder_returnsNegativeOne() {
        assertThat(filter.getOrder()).isEqualTo(-1);
    }

    @Nested
    @DisplayName("Public endpoints - bypassed without JWT")
    class PublicPaths {

        @ParameterizedTest
        @CsvSource({
                "POST, /api/auth/register",
                "POST, /api/auth/authenticate",
                "POST, /api/auth/refresh",
                "POST, /api/auth/logout",
                "GET, /actuator/health"
        })
        @DisplayName("Public paths pass through without token")
        void publicPaths_passThrough(String method, String path) {
            MockServerWebExchange exchange = exchangeWithoutAuth(method, path);

            filter.filter(exchange, chain).block();

            verify(chain).filter(any());
        }
    }

    @Nested
    @DisplayName("Invalid Authorization header - 401")
    class InvalidAuthHeader {

        @Test
        @DisplayName("Missing Authorization header -> 401")
        void missingAuthHeader_returns401() {
            MockServerWebExchange exchange = exchangeWithoutAuth("GET", "/api/me/profile");

            filter.filter(exchange, chain).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            verify(chain, never()).filter(any());
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "Basic abc123",
                "Bearer ",
                "Bearer not.a.jwt"
        })
        @DisplayName("Invalid Authorization header format -> 401")
        void invalidAuthHeaderFormat_returns401(String authHeaderValue) {
            MockServerWebExchange exchange = exchangeWithAuth("GET", "/api/me/profile", authHeaderValue);

            filter.filter(exchange, chain).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            verify(chain, never()).filter(any());
        }
    }

    @Nested
    @DisplayName("Valid ACCESS token - passes through with headers")
    class ValidToken {

        @Test
        @DisplayName("Valid token -> chain.filter() is called")
        void validAccessToken_passesThrough() {
            String token = generateValidAccessToken(42L, "test@test.com", "ROLE_USER");
            MockServerWebExchange exchange = exchangeWithAuth("GET", "/api/me/profile",
                    "Bearer " + token);

            filter.filter(exchange, chain).block();

            verify(chain).filter(any());
        }

        @Test
        @DisplayName("Valid ADMIN token -> passes through")
        void validAdminToken_passesThrough() {
            String token = generateValidAccessToken(1L, "admin@test.com", "ROLE_ADMIN");
            MockServerWebExchange exchange = exchangeWithAuth("GET", "/api/users/all",
                    "Bearer " + token);

            filter.filter(exchange, chain).block();

            verify(chain).filter(any());
        }
    }

    @Nested
    @DisplayName("Invalid token - 401")
    class InvalidToken {

        @Test
        @DisplayName("Expired token -> 401")
        void expiredToken_returns401() {
            String token = generateExpiredToken();
            MockServerWebExchange exchange = exchangeWithAuth("GET", "/api/me/profile",
                    "Bearer " + token);

            filter.filter(exchange, chain).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            verify(chain, never()).filter(any());
        }

        @Test
        @DisplayName("Token with wrong key -> 401")
        void wrongSignature_returns401() {
            String token = generateTokenWithWrongKey();
            MockServerWebExchange exchange = exchangeWithAuth("GET", "/api/me/profile",
                    "Bearer " + token);

            filter.filter(exchange, chain).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            verify(chain, never()).filter(any());
        }

        @Test
        @DisplayName("Token with wrong issuer -> 401")
        void wrongIssuer_returns401() {
            String token = generateTokenWithWrongIssuer();
            MockServerWebExchange exchange = exchangeWithAuth("GET", "/api/me/profile",
                    "Bearer " + token);

            filter.filter(exchange, chain).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            verify(chain, never()).filter(any());
        }

        @Test
        @DisplayName("REFRESH token instead of ACCESS -> 401")
        void refreshToken_returns401() {
            String token = generateRefreshToken();
            MockServerWebExchange exchange = exchangeWithAuth("GET", "/api/me/profile",
                    "Bearer " + token);

            filter.filter(exchange, chain).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            verify(chain, never()).filter(any());
        }
    }

    private String generateValidAccessToken(Long userId, String email, String role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(email)
                .claim("userId", userId)
                .claim("role", role)
                .claim("tokenType", "ACCESS")
                .issuer(ISSUER)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(3600)))
                .signWith(signingKey)
                .compact();
    }

    private String generateRefreshToken() {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject("test@test.com")
                .claim("userId", 1L)
                .claim("role", "ROLE_USER")
                .claim("tokenType", "REFRESH")
                .issuer(ISSUER)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(3600)))
                .signWith(signingKey)
                .compact();
    }

    private String generateExpiredToken() {
        Instant past = Instant.now().minusSeconds(3600);
        return Jwts.builder()
                .subject("expired@test.com")
                .claim("userId", 1L)
                .claim("role", "ROLE_USER")
                .claim("tokenType", "ACCESS")
                .issuer(ISSUER)
                .issuedAt(Date.from(past.minusSeconds(7200)))
                .expiration(Date.from(past))
                .signWith(signingKey)
                .compact();
    }

    private String generateTokenWithWrongIssuer() {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject("test@test.com")
                .claim("userId", 1L)
                .claim("role", "ROLE_USER")
                .claim("tokenType", "ACCESS")
                .issuer("wrong-issuer")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(3600)))
                .signWith(signingKey)
                .compact();
    }

    private String generateTokenWithWrongKey() {
        String differentSecret = "YW5vdGhlci1zZWNyZXQta2V5LWZvci10ZXN0aW5nLXB1cnBvc2VzLTQ1Ng==";
        SecretKey wrongKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(differentSecret));
        Instant now = Instant.now();
        return Jwts.builder()
                .subject("test@test.com")
                .claim("userId", 1L)
                .claim("role", "ROLE_USER")
                .claim("tokenType", "ACCESS")
                .issuer(ISSUER)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(3600)))
                .signWith(wrongKey)
                .compact();
    }

    private MockServerWebExchange exchangeWithAuth(String method, String path, String authHeader) {
        MockServerHttpRequest.BaseBuilder<?> builder = method.equals("GET")
                ? MockServerHttpRequest.get(path)
                : MockServerHttpRequest.post(path);

        if (authHeader != null) {
            builder.header(HttpHeaders.AUTHORIZATION, authHeader);
        }
        return MockServerWebExchange.from(builder.build());
    }

    private MockServerWebExchange exchangeWithoutAuth(String method, String path) {
        return exchangeWithAuth(method, path, null);
    }
}