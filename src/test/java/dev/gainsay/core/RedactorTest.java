package dev.gainsay.core;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class RedactorTest {

    @Test
    void masksAuthorizationHeaderButKeepsScheme() {
        String s = Redactor.sanitize("Authorization: Basic YWxpY2U6aHVudGVyMg==");
        assertEquals("Authorization: Basic ****", s);
    }

    @Test
    void masksPasswordLikeParameters() {
        String s = Redactor.sanitize("POST /login user=alice&password=hunter2&token=abc123&next=/home");
        assertFalse(s.contains("hunter2"));
        assertFalse(s.contains("abc123"));
        assertTrue(s.contains("user=alice"), "non-secret parameters stay readable");
        assertTrue(s.contains("password=****"));
    }

    @Test
    void masksCookieValuesButKeepsAttributes() {
        String s = Redactor.sanitize("Set-Cookie: SESSIONID=deadbeef; Path=/; HttpOnly");
        assertFalse(s.contains("deadbeef"));
        assertTrue(s.contains("Path=/"));
        assertTrue(s.contains("HttpOnly"));
    }

    @Test
    void masksProtocolLoginCommands() {
        assertEquals("PASS ****", Redactor.sanitize("PASS s3cret"));
        assertEquals("a1 LOGIN ****", Redactor.sanitize("a1 LOGIN bob s3cret"));
    }

    @Test
    void keepsWindowsSidsReadable() {
        assertTrue(Redactor.sanitize("SID=S-1-5-21-1-2-3-500").contains("S-1-5-21-1-2-3-500"));
    }

    @Test
    void escapesControlBytesAndTruncates() {
        String s = Redactor.sanitize("a\u0000b\nc" + "x".repeat(2000));
        assertTrue(s.startsWith("a\\x00b\\nc"));
        assertTrue(s.length() < Redactor.MAX_EVIDENCE_CHARS + 20);
    }

    @Test
    void hostileInputDoesNotBacktrack() {
        String evil = "Authorization: " + " ".repeat(5000) + "x" + "=".repeat(5000) + "password=" + "a".repeat(50_000);
        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> Redactor.sanitize(evil));
    }

    @Test
    void evidenceIsAlwaysSanitized() {
        Evidence e = new Evidence("packet", "10.0.0.1:80", "Cookie: sid2=abc; token=xyz", null);
        assertFalse(e.detail().contains("abc"));
        assertFalse(e.detail().contains("xyz"));
    }
}
