# Production-owned manifest dispatch

The native manifest session now delegates dispatch to the production
`garrett-core::dispatch` controller. Its private pending state owns the
request receipt and local send state; native primitives cannot edit either.
The native wrapper copies the returned receipt on success **and error**,
then returns the exact outcome. No `RefCell` borrow spans a primitive call.

The controller preserves the existing order: identity/target preparation,
audit attempt and durable audit callback, acknowledgment, header configuration,
fresh authority check, optional durable write reservation, provider setup,
current admission stamp, composite send-attempt gate, raw send, response,
optional durable write finish, then dispatch completion. Failed preparation
invokes no primitive. Each error retains its actual mutable work state and
receipt prefix. Write send/response failures and failed write finish retain
`OutcomeUnknown`; retries are never automatic. Wire versions, audit schema,
credential scope and optional coordinator deployment remain unchanged.

`proofs/GarrettDispatch.lean` checks this actual Rust extraction. Its returned
receipt proofs compose the concrete audit, provider, send and finish gates
through all returned outcomes. Refusal-prefix equations include denied audit,
rejected send gate and failed coordinator finish. The exact returned report
retains work, receipt, local attempt, provider stage and current stamp.
`proofs/GarrettDispatchSimulation.lean` composes this with owned completion and
the actual request entry: the former whole-dispatch and whole-completion
receipt assumptions follow from explicit native report/copy/outcome links.
Those links remain reviewed/tested adapter obligations, not universal native
correspondence proofs.

The primitive contracts remain explicit: Rust/compiler correctness; context
capture and conversion; clock/authority semantics; durable audit bytes and
acknowledgment; coordinator SQLite/mTLS behavior; TLS setup, `Write`, response
parsing and drop/unwind. A reported provider `Send` stage means its callback
was invoked; raw provider bytes require that callback's composite gate to
accept. Partial writes can expose bytes before an error, and receipts record
an attempt rather than guaranteed delivery. Setup can perform DNS/TCP/TLS
I/O before credentialed HTTP send. This result neither closes transitive I/O
reachability nor proves mediation of those setup/dependency effects.

Native tests cover all three read shapes, keyed writes, primitive failure
prefixes, replay rejection, zero/partial/flush write failures and retained
attempt state. The standalone synthetic HTTPS operator/guest workflow remains
an independent positive utility witness. Native JSON/selected-value/frame
observations, connected adaptive histories, NR-2/3/4/5 exit and independent
security review remain open. Installed vTPM tests do not establish physical
TPM custody, deployed VM isolation or real-provider compatibility.
