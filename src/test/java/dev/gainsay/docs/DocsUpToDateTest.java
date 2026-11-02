package dev.gainsay.docs;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Fails if docs/CHECKS.md no longer matches the check metadata; regenerate with DocsGenerator. */
class DocsUpToDateTest {

    @Test
    void checksDocMatchesCode() throws Exception {
        String onDisk = Files.readString(Path.of("docs", "CHECKS.md")).replace("\r\n", "\n");
        assertEquals(DocsGenerator.checks(), onDisk, "docs/CHECKS.md is stale: run DocsGenerator");
    }
}
