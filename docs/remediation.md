# 🛡️ Defense-in-Depth Remediation Blueprint

> **Target Architecture**: Spring Boot 3.2 (Java 21) • Next.js App Router • Shaka Packager Microservice • Cloudflare R2 & Workers

---

## 1. Remediated Target Architecture

To eliminate all six vulnerabilities (`FIND-01` through `FIND-06`) at their architectural root, we enforce **four defense-in-depth invariants**:
1. **Zero Public Access to Object Storage (`r2`)**: Disable public bucket access on Cloudflare R2; all reads must traverse a signed Cloudflare Worker or short-lived Presigned URLs (`X-Amz-Expires=300`).
2. **Zero Raw Key Exposure in Status/Metadata APIs**: Strip `encryptionKey` and `encryptionKeyId` from all status DTOs (`@JsonIgnore`). Deliver raw 16-byte AES-128 keys **exclusively** through an authenticated, enrollment-verified binary key endpoint (`GET /api/shaka/key/{videoId}`).
3. **Network-Layer Isolation for Transcoding Microservice (`shaka`)**: Place `shaka.media-core.example` behind an internal VPC / Cloudflare Zero Trust Service Token so only the Spring Boot backend can call `/api/media` or `/api/upload/*`.
4. **Strict Object-Level Authorization (`@PreAuthorize`)**: Enforce ownership and publication-state checks across `/api/documents/{id}/file`, `/api/book-orders/{id}/check-payment`, and Next.js RSC data-fetching layers.

```mermaid
flowchart LR
    Client(["👤 Authenticated Student"])
    subgraph Edge["Cloudflare Edge"]
        Worker["Signed Media Worker<br/>(Validates Short-Lived HMAC/JWT)"]
    end
    subgraph Core["Spring Boot 3.2 Core API"]
        KeyEndpoint["GET /api/shaka/key/{videoId}<br/>🔒 Verifies JWT + Course Enrollment"]
        StatusEndpoint["GET /api/shaka/status/{videoId}<br/>🔒 Role: ADMIN/TEACHER (No Key in DTO)"]
    end
    subgraph PrivateNet["Private VPC / mTLS Only"]
        Shaka["Shaka Transcoder"]
        R2[("Private Cloudflare R2 Bucket")]
    end

    Client -->|1. Fetches #EXT-X-KEY (16B binary)| KeyEndpoint
    Client -->|2. Fetches Signed .m3u8 & .ts| Worker
    Worker -->|S3v4 Internal Binding| R2
    KeyEndpoint -->|Internal mTLS| Shaka
    StatusEndpoint -->|Internal mTLS| Shaka
```

---

## 2. Concrete Code Patches

### 2.1. Spring Boot 3.2: Lock Down `SecurityFilterChain` & Remove `encryptionKey` from Status DTO (`FIND-01`, `FIND-04`, `FIND-05`)

```java
package vn.edtech.lms.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // FIX FIND-01: Restrict transcoding status strictly to ADMIN/TEACHER
                .requestMatchers("/api/shaka/status/**").hasAnyRole("ADMIN", "TEACHER")
                // FIX FIND-01: Require authentication for HLS key & token delivery
                .requestMatchers("/api/shaka/token", "/api/shaka/key/**").authenticated()
                // FIX FIND-05: Require authentication for order payment verification
                .requestMatchers("/api/book-orders/*/check-payment").authenticated()
                .requestMatchers("/api/course-orders/installments/*/check-payment").authenticated()
                // Public endpoints with explicit service-layer state checks
                .requestMatchers(HttpMethod.GET, "/api/documents/*/preview").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}
```

#### Strip Cryptographic Keys from Status DTO & Enforce Enrollment on Key Delivery:
```java
package vn.edtech.lms.shaka;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.Base64;
import java.util.UUID;

public record ShakaVideoStatusDto(
    UUID id,
    String originalName,
    String status,
    @JsonIgnore String encryptionKey,    // NEVER serialize raw AES-128 key in JSON status
    @JsonIgnore String encryptionKeyId
) {}

@RestController
@RequestMapping("/api/shaka")
public class ShakaKeyController {

    private final EnrollmentService enrollmentService;
    private final ShakaInternalClient shakaClient;

    public ShakaKeyController(EnrollmentService enrollmentService, ShakaInternalClient shakaClient) {
        this.enrollmentService = enrollmentService;
        this.shakaClient = shakaClient;
    }

    /**
     * Secure HLS #EXT-X-KEY endpoint: returns raw 16-byte AES-128 key ONLY if the
     * authenticated student is enrolled in a course containing this videoId.
     */
    @GetMapping("/key/{videoId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<byte[]> getDecryptionKey(
            @PathVariable UUID videoId,
            @AuthenticationPrincipal UserPrincipal currentUser) {

        if (!enrollmentService.canUserWatchVideo(currentUser.getId(), videoId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        String base64Key = shakaClient.fetchInternalEncryptionKey(videoId);
        byte[] rawKeyBytes = Base64.getDecoder().decode(base64Key);

        return ResponseEntity.ok()
            .header(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate")
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .body(rawKeyBytes);
    }
}
```

---

### 2.2. Cloudflare Worker: Disable Public R2 & Enforce Short-Lived Signed Tokens (`FIND-02`)

1. In the Cloudflare Dashboard (**R2 $\rightarrow$ Bucket Settings**), **disable** `Public Bucket Access` (`r2.dev` subdomain and custom public domain `r2.storage-edge.example`).
2. Bind the R2 bucket privately (`env.R2_MEDIA_BUCKET`) to the `media.storage-edge.example` Worker and verify an HMAC-SHA256 / JWT token bound to both `videoId` and expiration timestamp:

```javascript
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const token = url.searchParams.get("token");
    if (!token) {
      return new Response(JSON.stringify({ error: "Missing playback token" }), { status: 401 });
    }

    // Verify JWT signature and ensure token's allowedVideoId matches requested path
    const payload = await verifyPlaybackJwt(token, env.PLAYBACK_JWT_SECRET);
    if (!payload || !url.pathname.startsWith(`/hls/${payload.videoId}/`)) {
      return new Response(JSON.stringify({ error: "Forbidden resource scope" }), { status: 403 });
    }

    const objectKey = url.pathname.replace(/^\//, "");
    const object = await env.R2_MEDIA_BUCKET.get(objectKey);
    if (!object) {
      return new Response("Not Found", { status: 404 });
    }

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("Cache-Control", "private, max-age=60");
    return new Response(object.body, { headers });
  }
};
```

---

### 2.3. Remediating Document BOLA & Next.js RSC Over-Posting (`FIND-04`, `FIND-06`)

1. **Document Streaming Guard (`FIND-04`)**:
   - In `DocumentService.getDocumentStream(UUID documentId, UserPrincipal user)`, verify `doc.getStatus() == PublicationStatus.PUBLISHED` (preventing access to replaced/archived records) and check `doc.isPublicFree() || enrollmentService.hasAccess(user, documentId)`.
2. **Next.js Server Component DTO Filtering (`FIND-06`)**:
   - Never pass raw ORM/JPA entities directly into Next.js Server Component props. Filter out any entity where `status === 'DRAFT'` on the backend API before returning JSON to the Next.js SSR layer, and strip internal lesson UUIDs for unauthenticated course preview requests.

---

## 3. Prioritized Remediation Roadmap

| Priority Phase | SLA Target | Action Items | Mitigated Findings |
| :--- | :---: | :--- | :---: |
| **Phase 1: Emergency Containment** | **< 24 Hours** | 1. Disable Public Access on `r2.storage-edge.example`.<br>2. Restrict `shaka.media-core.example` (`/api/media`, `/api/auth/token`, `/api/upload/*`) to backend IP via Cloudflare WAF / mTLS.<br>3. Block unauthenticated access to `/api/shaka/status/**` in Spring Security. | `FIND-01`<br>`FIND-02`<br>`FIND-03` |
| **Phase 2: Access Control Hardening** | **< 7 Days** | 1. Enforce `PUBLISHED` state and user authorization on `/api/documents/{id}/file`.<br>2. Add `@PreAuthorize("@orderSecurity.isOwner(#orderId, principal)")` on payment-check endpoints.<br>3. Filter `DRAFT` records from RSC responses. | `FIND-04`<br>`FIND-05`<br>`FIND-06` |
| **Phase 3: Cryptographic Key Rotation** | **< 30 Days** | 1. Re-encrypt HLS streams whose `encryptionKey` was previously exposed via `/api/media`.<br>2. Migrate seeded sequential UUIDs (`a0000000-...`, `c1000000-...`) to cryptographically random UUIDv4/UUIDv7 values. | Defense-in-Depth |
