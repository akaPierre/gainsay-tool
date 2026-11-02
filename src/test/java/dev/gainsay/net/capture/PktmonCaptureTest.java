package dev.gainsay.net.capture;

import dev.gainsay.net.synth.Scenarios;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Orchestration of Windows Packet Monitor, verified with a fake command runner (no admin, no Windows needed). */
class PktmonCaptureTest {

    static final class FakeRunner implements CommandRunner {
        final List<List<String>> calls = new ArrayList<>();
        int startExit = 0;
        Path writePcapTo;

        @Override
        public Result run(List<String> command, java.time.Duration timeout) throws IOException {
            calls.add(command);
            String verb = command.get(1);
            if (verb.equals("start")) {
                return new Result(startExit, startExit == 0 ? "" : "Error: Packet monitor is already running.");
            }
            if (verb.equals("etl2pcap") && writePcapTo != null) {
                Scenarios.brief().write(Path.of(command.get(command.indexOf("--out") + 1)));
            }
            return new Result(0, "");
        }

        List<String> verbs() {
            return calls.stream().map(c -> c.get(1)).toList();
        }
    }

    @Test
    void startsOnNicsOnlyStopsAndConverts(@TempDir Path dir) throws Exception {
        FakeRunner r = new FakeRunner();
        r.writePcapTo = dir;
        Path pcapng;
        try (PktmonCapture p = new PktmonCapture(r, "pktmon.exe", dir)) {
            p.start();
            assertTrue(p.running());
            pcapng = p.stopAndConvert();
            assertFalse(p.running());
        }
        assertEquals(List.of("start", "stop", "etl2pcap"), r.verbs(), "no extra stop after a clean stop");
        List<String> start = r.calls.get(0);
        assertTrue(start.containsAll(List.of("--capture", "--comp", "nics", "--pkt-size", "0", "--file-name")));
        assertFalse(start.contains("filter"), "Gainsay never adds pktmon filters");
        assertTrue(Files.exists(pcapng));
        try (PcapFileSource src = new PcapFileSource(pcapng)) {
            assertNotNull(src.next());
        }
    }

    @Test
    void alwaysStopsWhatItStartedEvenOnFailure(@TempDir Path dir) throws Exception {
        FakeRunner r = new FakeRunner();
        try (PktmonCapture p = new PktmonCapture(r, "pktmon.exe", dir)) {
            p.start();
            // analysis blows up before stopAndConvert is reached
        }
        assertEquals(List.of("start", "stop"), r.verbs());
    }

    @Test
    void leavesSomeoneElsesSessionAlone(@TempDir Path dir) {
        FakeRunner r = new FakeRunner();
        r.startExit = 1;
        IOException e = assertThrows(IOException.class, () -> {
            try (PktmonCapture p = new PktmonCapture(r, "pktmon.exe", dir)) {
                p.start();
            }
        });
        assertTrue(e.getMessage().contains("already running"));
        assertEquals(List.of("start"), r.verbs(), "a session we did not start is never stopped");
    }
}
