
package com.krakedev.jwt.services;

import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    public Usuario registrar(String username, String password, String rol) {

        if (usuarioRepository.existsByUsername(username)) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "El usuario ya existe"
            );
        }

        Usuario usuario = new Usuario();

        usuario.setUsername(username);

        String passwordHash = BCrypt.hashpw(
                password,
                BCrypt.gensalt(12)
        );

        usuario.setPassword(passwordHash);
        usuario.setRol(rol);

        return usuarioRepository.save(usuario);
    }

    public Optional<Usuario> login(String username, String password) {

        Optional<Usuario> usuarioOptional =
                usuarioRepository.findByUsername(username);

        if (usuarioOptional.isEmpty()) {
            return Optional.empty();
        }

        Usuario usuario = usuarioOptional.get();

        boolean passwordCorrecta = BCrypt.checkpw(
                password,
                usuario.getPassword()
        );

        if (passwordCorrecta) {
            return Optional.of(usuario);
        }

        return Optional.empty();
    }
}
