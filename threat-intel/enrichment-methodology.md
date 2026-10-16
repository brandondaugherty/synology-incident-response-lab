# Threat-Intelligence Enrichment Methodology

## Purpose

Enrichment adds context to a security event. It does not prove that an address belongs to a specific attacker or that every system in a network is malicious.

## Sources Used

- **IPinfo:** registration, ASN, network-owner, and geography context
- **AlienVault OTX:** presence in community threat-intelligence pulses

Only public source IP addresses were submitted. No private addresses, usernames, hostnames, file paths, or NAS configuration data were sent to enrichment providers.

## Sampling

The five most frequently observed /24 network clusters were assigned synthetic labels `NET-01` through `NET-05`. One representative address from each cluster was passively enriched. Raw addresses are not published.

## Results

- The five clusters produced **223 Auto Block events**.
- Representatives resolved to hosting/network-provider space in Germany and the Netherlands.
- Four of five representatives appeared in AlienVault OTX pulses at the time of analysis.
- The repeated appearance of related address space, combined with unique individual source addresses, is consistent with rotating or distributed scanning infrastructure.

## Analytic Caveats

- IP geolocation can be imprecise and reflects infrastructure location, not operator location.
- ASN ownership can change.
- An OTX pulse is a lead, not a verdict; it can be stale, incomplete, or contextual.
- Shared hosting and proxy infrastructure can serve unrelated users.
- No active scanning or interaction with source systems was performed.
- No attribution is made to a person, organization, or nation.

## Repeatable Workflow

1. Confirm that the indicator is public and appropriate to share with the provider.
2. Record the observation time and source evidence.
3. Query registration/ASN context.
4. Check one or more reputation sources.
5. Correlate the result with local telemetry.
6. Record confidence and limitations.
7. Make response decisions from local risk and evidence, not reputation alone.
