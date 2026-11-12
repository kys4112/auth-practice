package me.kys.authpractice;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
public class ApiController {

    public record UserAccount(long id, String username, String password, String role) {
    }

    public record Post(long id, long ownerId, String title) {
    }

    private final JwtUtil jwtUtil;

    private final List<UserAccount> users = List.of(
            new UserAccount(1, "kim", "1234", "user"),
            new UserAccount(2, "lee", "1234", "user"),
            new UserAccount(3, "admin", "admin1234", "admin"));

    private final List<Post> posts = new ArrayList<>(List.of(
            new Post(1, 1, "김의 글"),
            new Post(2, 2, "이의 글")));

    public ApiController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        for (UserAccount u : users) {
            if (u.username().equals(body.get("username")) && u.password().equals(body.get("password"))) {
                String token = jwtUtil.create(u.id(), u.username(), u.role());
                return ResponseEntity.ok(Map.of("token", token));
            }
        }
        return ResponseEntity.status(401).body(Map.of("message", "아이디 또는 비밀번호 오류"));
    }

    @GetMapping("/me")
    public AuthUser me(@AuthenticationPrincipal AuthUser user) {
        return user;
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> admin() {
        return Map.of("message", "관리자 페이지");
    }

    @PutMapping("/posts/{id}")
    public ResponseEntity<?> update(@PathVariable("id") long id,
                                    @RequestBody Map<String, String> body,
                                    @AuthenticationPrincipal AuthUser user) {
        Post post = null;
        for (Post p : posts) {
            if (p.id() == id) {
                post = p;
            }
        }
        if (post == null) {
            return ResponseEntity.status(404).body(Map.of("message", "게시글 없음"));
        }
        if (post.ownerId() != user.id() && !user.role().equals("admin")) {
            return ResponseEntity.status(403).body(Map.of("message", "본인 글만 수정할 수 있습니다."));
        }
        Post updated = new Post(post.id(), post.ownerId(), body.get("title"));
        posts.set(posts.indexOf(post), updated);
        return ResponseEntity.ok(updated);
    }
}