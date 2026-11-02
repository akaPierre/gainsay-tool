package dev.gainsay.net.capture;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Live capture through pcap4j (JNA binding to libpcap on Linux/macOS, Npcap on Windows). This class
 * and {@link #listInterfaces()} are the only native boundary in Gainsay; everything else is pure Java.
 *
 * <p>Capture is strictly passive: the handle is opened read-only in promiscuous mode, no packet is ever
 * sent, and no filter, route or interface setting is changed. Opening it normally needs root
 * (or CAP_NET_RAW) on Linux and Administrator + Npcap on Windows.
 */
public final class LiveCaptureSource implements PacketSource {

    static final int SNAPLEN = 65_536;
    static final int READ_TIMEOUT_MS = 200;

    private final PcapHandle handle;
    private final String name;
    private final long deadlineNanos;
    private final int linkType;

    private LiveCaptureSource(PcapHandle handle, String name, Duration duration) {
        this.handle = handle;
        this.name = name + " (" + duration.toSeconds() + " s)";
        this.deadlineNanos = System.nanoTime() + duration.toNanos();
        this.linkType = handle.getDlt().value();
    }

    /** Opens an interface by name for a fixed duration. */
    public static LiveCaptureSource open(String iface, Duration duration) throws IOException {
        configureNpcap();
        try {
            PcapNetworkInterface nif = Pcaps.getDevByName(iface);
            if (nif == null) {
                throw new IOException("no capture interface named '" + iface + "' (see: gainsay list-ifaces)");
            }
            PcapHandle h = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS);
            return new LiveCaptureSource(h, "live " + iface, duration);
        } catch (PcapNativeException e) {
            throw new IOException("cannot open " + iface + ": " + e.getMessage() + " (live capture needs root/Administrator)", e);
        } catch (LinkageError e) {
            throw new IOException(nativeMissing(), e);
        }
    }

    /** One line per interface: name, description and addresses. */
    public static List<String> listInterfaces() throws IOException {
        configureNpcap();
        try {
            List<String> out = new ArrayList<>();
            for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
                List<String> addrs = new ArrayList<>();
                for (PcapAddress a : nif.getAddresses()) {
                    if (a.getAddress() != null) {
                        addrs.add(a.getAddress().getHostAddress());
                    }
                }
                out.add(nif.getName() + (nif.getDescription() == null ? "" : "  — " + nif.getDescription())
                        + (addrs.isEmpty() ? "" : "  [" + String.join(", ", addrs) + "]"));
            }
            return out;
        } catch (PcapNativeException e) {
            throw new IOException("cannot list interfaces: " + e.getMessage(), e);
        } catch (LinkageError e) {
            throw new IOException(nativeMissing(), e);
        }
    }

    /** On Windows, whether Npcap/WinPcap DLLs are installed; elsewhere assume libpcap may be present. */
    public static boolean nativeLikelyAvailable() {
        String root = System.getenv("SystemRoot");
        if (root == null) {
            return true;
        }
        return Files.exists(Path.of(root, "System32", "Npcap", "wpcap.dll")) || Files.exists(Path.of(root, "System32", "wpcap.dll"));
    }

    /** Name of the capture interface that carries one of the given addresses, or null. */
    public static String interfaceFor(java.util.Collection<String> ips) throws IOException {
        configureNpcap();
        try {
            for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
                for (PcapAddress a : nif.getAddresses()) {
                    if (a.getAddress() != null && ips.contains(dev.gainsay.core.Addresses.canonical(a.getAddress().getHostAddress()))) {
                        return nif.getName();
                    }
                }
            }
            return null;
        } catch (PcapNativeException e) {
            throw new IOException("cannot list interfaces: " + e.getMessage(), e);
        } catch (LinkageError e) {
            throw new IOException(nativeMissing(), e);
        }
    }

    @Override
    public RawFrame next() throws IOException {
        while (System.nanoTime() < deadlineNanos) {
            try {
                byte[] data = handle.getNextRawPacket();
                if (data == null) {
                    continue; // read timeout; check the deadline again
                }
                Timestamp ts = handle.getTimestamp();
                Instant t = ts == null ? Instant.now() : ts.toInstant();
                return new RawFrame(t, linkType, data, data.length);
            } catch (NotOpenException e) {
                throw new IOException("capture handle closed", e);
            }
        }
        return null;
    }

    @Override
    public String describe() {
        return name;
    }

    @Override
    public void close() {
        handle.close();
    }

    /**
     * On Windows, Npcap installs its DLLs in System32\Npcap rather than System32 unless "WinPcap
     * compatible mode" was chosen. Point pcap4j at them if present (read-only lookup, no system change).
     */
    static void configureNpcap() {
        String root = System.getenv("SystemRoot");
        if (root == null || System.getProperty("org.pcap4j.core.pcapLibName") != null) {
            return;
        }
        Path dir = Path.of(root, "System32", "Npcap");
        if (Files.exists(dir.resolve("wpcap.dll"))) {
            System.setProperty("org.pcap4j.core.pcapLibName", dir.resolve("wpcap.dll").toString());
            System.setProperty("org.pcap4j.core.packetLibName", dir.resolve("Packet.dll").toString());
        }
    }

    private static String nativeMissing() {
        return "libpcap/Npcap is not available. Install libpcap (Linux/macOS) or Npcap (Windows, https://npcap.com) for live capture, "
                + "or analyse a file with --pcap.";
    }
}
