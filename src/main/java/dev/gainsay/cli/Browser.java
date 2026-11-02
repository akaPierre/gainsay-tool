package dev.gainsay.cli;

import java.awt.Desktop;
import java.io.PrintWriter;
import java.nio.file.Path;

/** Opens a local report file in the default browser. Never fetches anything from the network. */
final class Browser {

    private Browser() {
    }

    static void open(Path file, PrintWriter o) {
        Path abs = file.toAbsolutePath();
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(abs.toUri());
                return;
            }
        } catch (Exception | LinkageError e) {
            // headless or no desktop integration: fall through
        }
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            ProcessBuilder pb = os.startsWith("windows") ? new ProcessBuilder("explorer.exe", abs.toString())
                    : os.contains("mac") ? new ProcessBuilder("open", abs.toString()) : new ProcessBuilder("xdg-open", abs.toString());
            pb.start();
        } catch (Exception e) {
            o.println("Open the report in your browser: " + abs.toUri());
        }
    }
}
