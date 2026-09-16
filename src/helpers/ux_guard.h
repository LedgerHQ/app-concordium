#pragma once

/**
 * Run a UI approval continuation so that a thrown status word becomes a reply, not an app exit.
 *
 * dispatch_guarded() in app_main.c does this for a dispatch, but it wraps apdu_dispatcher() and
 * nothing else. An approval callback runs later, from the BOLOS UX loop, after that TRY context
 * has been popped: a THROW from one unwinds to the SDK's handler in standalone_app_main(), which
 * exits the application - the V-006 failure mode, reached from the approve button instead of
 * from an APDU. Nearly every continuation can get there, some in one step
 * (buildAndSignTransactionHash(), processNextScheduledAmount(), send_public_key(),
 * confirmAttribute()) and the rest through the cx_* helpers, so the two display backends route
 * them all through here rather than each converting its own THROWs.
 *
 * On a caught status word the flow ends the way dispatch_guarded() ends one - context union
 * wiped, instruction released, so a later packet cannot resume a half-reviewed transaction -
 * the host is answered, and the UI returns to the idle screen, since the review it was showing
 * is gone. A BOLOS system exception is re-raised: those are genuine faults the SDK has to see.
 *
 * A continuation that has already replied before throwing would make this a second reply. None
 * do today: every THROW on these paths is reached before the send.
 */
void ux_run_guarded(void (*continuation)(void));
