package com.techchallenge.auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import org.json.JSONObject;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.Date;

public class TokenIssuerHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final String host = System.getenv("DB_HOST");
    private final String username = System.getenv("DB_USER");
    private final String password = System.getenv("DB_PASSWORD");
    private final String database = System.getenv().getOrDefault("DB_NAME", "tech_challenge");
    private final String jwtSecret = System.getenv("JWT_SECRET");
    private final int tokenTtlSeconds = Integer.parseInt(System.getenv().getOrDefault("JWT_TTL_SECONDS","900"));

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {

        try {
            JSONObject body = new JSONObject(event.getBody() == null ? "{}" : event.getBody());
            String cpf = body.optString("cpf", null);
            if (cpf == null || cpf.isBlank()) {
                return new APIGatewayProxyResponseEvent().withStatusCode(400)
                        .withBody("{\"error\":\"cpf is required\"}");
            }

            if (host == null || host.isBlank()) {
                return new APIGatewayProxyResponseEvent().withStatusCode(500)
                        .withBody("{\"error\":\"DB_HOST not provided in env or secret\"}");
            }

            String jdbcUrl = String.format("jdbc:mysql://%s:3306/%s?useSSL=false&serverTimezone=UTC", host, database);

            boolean exists;
            try (Connection conn = DriverManager.getConnection(jdbcUrl, username, password);
                 PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM clientes WHERE cpf = ? LIMIT 1")) {
                ps.setString(1, cpf);
                try (ResultSet rs = ps.executeQuery()) {
                    exists = rs.next();
                }
            }

            if (!exists) {
                return new APIGatewayProxyResponseEvent().withStatusCode(404).withBody("{\"error\":\"cliente not found\"}");
            }

            // create JWT
            Algorithm alg = Algorithm.HMAC256(jwtSecret);
            Instant now = Instant.now();
            String token = JWT.create()
                    .withClaim("cpf", cpf)
                    .withIssuedAt(Date.from(now))
                    .withExpiresAt(Date.from(now.plusSeconds(tokenTtlSeconds)))
                    .sign(alg);

            JSONObject resp = new JSONObject();
            resp.put("token", token);
            resp.put("expires_in", tokenTtlSeconds);

            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(200)
                    .withBody(resp.toString());

        } catch (Exception e) {
            context.getLogger().log("Erro: " + e.getMessage());
            JSONObject err = new JSONObject();
            err.put("error", "internal_error");
            err.put("detail", e.getMessage());
            return new APIGatewayProxyResponseEvent().withStatusCode(500).withBody(err.toString());
        }
    }
}
