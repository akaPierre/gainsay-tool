package dev.gainsay.cli;

import dev.gainsay.net.capture.LiveCaptureSource;
import picocli.CommandLine.Command;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "list-ifaces", description = "List capture interfaces (needs libpcap on Linux/macOS or Npcap on Windows).")
public final class ListIfacesCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Override
    public Integer call() throws Exception {
        List<String> ifaces = LiveCaptureSource.listInterfaces();
        var out = spec.commandLine().getOut();
        if (ifaces.isEmpty()) {
            out.println("No capture interfaces visible (try an elevated prompt).");
        }
        ifaces.forEach(out::println);
        out.println();
        out.println("For a multi-NIC monitoring placement (bridge, router or SPAN port), see README.md#placing-the-monitor.");
        return 0;
    }
}
