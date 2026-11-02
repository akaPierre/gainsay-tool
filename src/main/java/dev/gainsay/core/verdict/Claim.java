package dev.gainsay.core.verdict;

import dev.gainsay.core.HostIdentity;

/**
 * A host's testimony about one network-visible behaviour.
 *
 * @param type      what is being claimed (and therefore which evidence can test it)
 * @param host      who claims it
 * @param secure    true if the configured state is the safe one (e.g. "SMB1 server disabled")
 * @param statement human-readable claim, e.g. "SMB1 server: disabled (Get-SmbServerConfiguration)"
 * @param strength  how firmly it is configured
 * @param basis     where the claim was read (registry path, cmdlet)
 * @param checkId   the HOST check that produced it
 */
public record Claim(
        ClaimType type,
        HostIdentity host,
        boolean secure,
        String statement,
        ClaimStrength strength,
        String basis,
        String checkId) {
}
