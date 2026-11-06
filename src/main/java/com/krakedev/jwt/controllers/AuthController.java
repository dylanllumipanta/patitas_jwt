
package com.krakedev.jwt.controllers;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.jwt.services.UsuarioService;
import com.krakedev.jwt.utils.JwtUtil;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UsuarioService usuarioService;
    private final JwtUtil jwtUtil;

    public AuthController(
            UsuarioService usuarioService,
            JwtUtil jwtUtil) {

        this.usuarioService = usuarioService;
        this.jwtUtil = jwtUtil;
    }

    public record RegistroRequest(
            String username,
            String password,
            String rol) {
    }

    public record LoginRequest(
            String username,
            String password) {
    }

    @PostMapping("/registrar")
    public ResponseEntity<?> registrar(
            @RequestBody RegistroRequest datos) {

        if (datos.username() == null ||
                datos.username().isBlank() ||
                datos.password() == null ||
                datos.password().isBlank() ||
                datos.rol() == null) {

            return ResponseEntity.badRequest()
                    .body(Map.of("mensaje", "Datos incompletos"));
        }

        if (!"ADMIN".equals(datos.rol()) &&
                !"USER".equals(datos.rol())) {

            return ResponseEntity.badRequest()
                    .body(Map.of("mensaje", "Rol no válido"));
        }

        if (datos.username().length() > 50 ||
                datos.password().getBytes(StandardCharsets.UTF_8).length > 72) {

            return ResponseEntity.badRequest()
                    .body(Map.of("mensaje", "Datos demasiado largos"));
        }

        usuarioService.registrar(
                datos.username(),
                datos.password(),
                datos.rol()
        );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("mensaje", "Usuario registrado correctamente"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest datos) {

        if (datos.username() == null ||
                datos.password() == null) {

            return ResponseEntity.badRequest()
                    .body(Map.of("mensaje", "Credenciales requeridas"));
        }

        var usuarioOptional = usuarioService.login(
                datos.username(),
                datos.password()
        );

        if (usuarioOptional.isEmpty()) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("mensaje", "Credenciales incorrectas"));
        }

        var usuario = usuarioOptional.get();

        String token = jwtUtil.generarToken(
                usuario.getUsername(),
                usuario.getRol()
        );

        return ResponseEntity.ok(
                Map.of(
                        "mensaje", "Login correcto",
                        "token", token,
                        "tipo", "Bearer",
                        "expiraEnMinutos", 30
                )
        );
    }

    @GetMapping("/perfil")
    public ResponseEntity<?> perfil(
            @RequestHeader(value = "Authorization", required = false)
            String authorization) {

        if (authorization == null ||
                !authorization.startsWith("Bearer ")) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("mensaje", "Token requerido"));
        }

        try {

            String token = authorization.substring(7);

            DecodedJWT jwt = jwtUtil.verificarToken(token);

            String username = jwt.getSubject();
            String rol = jwt.getClaim("rol").asString();

            String saludo;

            if ("ADMIN".equals(rol)) {
                saludo = "Bienvenido voluntario del refugio";
            } else if ("USER".equals(rol)) {
                saludo = "Bienvenido adoptante de Patitas al Rescate";
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("mensaje", "Rol no válido"));
            }

            return ResponseEntity.ok(
                    Map.of(
                            "mensaje", saludo,
                            "username", username,
                            "rol", rol
                    )
            );

        } catch (JWTVerificationException e) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("mensaje", "Token inválido o expirado"));
        }
    }
}
