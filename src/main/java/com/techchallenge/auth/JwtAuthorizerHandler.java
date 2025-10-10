package com.techchallenge.auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponse;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponse.Statement;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponse.PolicyDocument;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class JwtAuthorizerHandler implements RequestHandler<Map<String,Object>, IamPolicyResponse> {

    private final String jwtSecret = System.getenv("JWT_SECRET");

    @Override
    public IamPolicyResponse handleRequest(Map<String,Object> event, Context context) {
        try {
            Map headers = (Map) event.get("headers");
            if (headers == null) return generatePolicy("unknown","Deny","*");

            String auth = (String) headers.getOrDefault("authorization", headers.get("Authorization"));
            if (auth == null || !auth.startsWith("Bearer ")) {
                return generatePolicy("unknown","Deny","*");
            }
            String token = auth.substring(7);

            Algorithm alg = Algorithm.HMAC256(jwtSecret);
            DecodedJWT jwt = JWT.require(alg).build().verify(token);

            String cpf = jwt.getClaim("cpf").asString();
            if (cpf == null || cpf.isBlank()) return generatePolicy("unknown","Deny","*");

            String methodArn = (String) event.get("methodArn");
            // Ajusta resource para liberar todas as rotas no stage:
            String resource = methodArn.substring(0, methodArn.lastIndexOf("/")) + "/*";

            return generatePolicy(cpf,"Allow", resource);
        } catch (Exception e) {
            context.getLogger().log("JWT validation failed: " + e.getMessage());
            return generatePolicy("unknown","Deny","*");
        }
    }

    private IamPolicyResponse generatePolicy(String principalId, String effect, String resource) {

        Statement statement = new Statement();
        statement.setAction("execute-api:Invoke");
        statement.setEffect(effect);
        statement.setResource(Collections.singletonList(resource));

        PolicyDocument policyDocument = new PolicyDocument();
        policyDocument.setVersion("2012-10-17");
        policyDocument.setStatement(Arrays.asList(statement));

        IamPolicyResponse policy = new IamPolicyResponse();
        policy.setPrincipalId(principalId);
        policy.setPolicyDocument(policyDocument);

        return policy;
    }
}
