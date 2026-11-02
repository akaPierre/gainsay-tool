package dev.gainsay.cli;

import dev.gainsay.core.Json;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "init", description = "Write an example gainsay.json (segments, internal DNS servers, thresholds) to edit.")
public final class InitCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Option(names = "--file", paramLabel = "FILE", description = "Where to write it (default ${DEFAULT-VALUE}).", defaultValue = GainsayConfig.DEFAULT_FILE)
    Path file;

    @Option(names = "--force", description = "Overwrite an existing file.")
    boolean force;

    @Override
    public Integer call() throws Exception {
        var out = spec.commandLine().getOut();
        if (Files.exists(file) && !force) {
            out.println(file + " already exists; use --force to overwrite it.");
            return 2;
        }
        Json.MAPPER.writeValue(file.toFile(), GainsayConfig.example());
        out.println("Wrote " + file + ". Edit the segments and expectedResolvers to match your network, then run: gainsay audit");
        return 0;
    }
}
