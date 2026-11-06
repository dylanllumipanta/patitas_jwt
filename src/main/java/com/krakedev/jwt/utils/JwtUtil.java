
package com.krakedev.jwt.utils;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@Component
public class JwtUtil {

    private final Algorithm algorithm;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        this.algorithm = Algorithm.HMAC256(secret);
    }

    public String generarToken(String username, String rol) {

        Date fechaActual = new Date();

        Date fechaExpiracion = new Date(
                fechaActual.getTime() + 30 * 60 * 1000
        );

        return JWT.create()
                .withSubject(username)
                .withClaim("rol", rol)
                .withIssuedAt(fechaActual)
                .withExpiresAt(fechaExpiracion)
                .sign(algorithm);
    }

    public DecodedJWT verificarToken(String token) {

        return JWT.require(algorithm)
                .build()
                .verify(token);
    }
}
