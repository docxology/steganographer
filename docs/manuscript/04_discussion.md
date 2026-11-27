# Discussion

A valid signature checks that an artifact agrees with the signed input
under a given key. Establishing who controls that key and whether it was
trusted at capture time requires separate evidence. Preserving the exact
artifact and its relevant metadata makes later replay possible.
Sampling can leave intervals that have no signed artifact.

The experiment exercises core cryptography on synthetic bytes. A deployment
can separately inspect capture, packaging, decoder behavior, and metadata
custody. Those checks cover parts of the capture and delivery path outside
this fixture.
