"""Command line entry point for the key exchange.

    python -m akex handshake     run a handshake and use the session
    python -m akex attacks       run every adversary simulation
"""

import argparse
import sys

from .attacks import run_all
from .channel import AuthenticatedChannel
from .params import GROUPS, get_group
from .protocol import Initiator, Responder
from .wire import ConfirmMessage, InitMessage, ResponseMessage


def _rule(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}"


def cmd_handshake(args: argparse.Namespace) -> int:
    """Run one handshake message by message, printing the wire exchange."""
    group = get_group(args.group)
    psk = args.psk.encode()
    initiator = Initiator(psk=psk, group=group)
    responder = Responder(psk=psk, group=group)

    print(_rule("AKEX handshake"))
    print(f"group:  MODP-{group.bits} (id {group.group_id})")
    print(f"psk:    {len(psk)} bytes")

    init_msg = initiator.start()
    on_wire = init_msg.encode()
    print(f"\n  1. I -> R  init      {len(on_wire):>4} bytes  "
          f"nonce_i={init_msg.nonce_i[:8].hex()}...  g^i={init_msg.pub_i[:8].hex()}...")

    # Decode from bytes at each hop: the parties only ever see the wire form.
    response, _ = responder.respond(InitMessage.decode(on_wire))
    on_wire = response.encode()
    print(f"  2. R -> I  response  {len(on_wire):>4} bytes  "
          f"nonce_r={response.nonce_r[:8].hex()}...  tag_r={response.tag_r[:8].hex()}...")

    confirm, initiator_keys = initiator.finish(ResponseMessage.decode(on_wire))
    on_wire = confirm.encode()
    print(f"  3. I -> R  confirm   {len(on_wire):>4} bytes  "
          f"tag_i={confirm.tag_i[:8].hex()}...")

    responder_keys = responder.confirm(ConfirmMessage.decode(on_wire))

    print(_rule("Derived keys"))
    if initiator_keys != responder_keys:
        print("MISMATCH: the two sides derived different keys")
        return 1
    print(f"both sides agree; session fingerprint {initiator_keys.fingerprint()}")
    for label, key in (
        ("auth_i      ", initiator_keys.auth_i),
        ("auth_r      ", initiator_keys.auth_r),
        ("session_i2r ", initiator_keys.session_i2r),
        ("session_r2i ", initiator_keys.session_r2i),
    ):
        # First bytes only. Enough to show the keys differ, not enough to be
        # a habit worth forming with real key material.
        print(f"  {label} {key[:12].hex()}...  ({len(key) * 8} bits)")

    print(_rule("Authenticated session"))
    sender = AuthenticatedChannel.for_initiator(initiator_keys)
    receiver = AuthenticatedChannel.for_responder(responder_keys)
    for text in (b"application message one", b"application message two"):
        record = sender.seal(text)
        delivered = receiver.open_record(record)
        print(f"  seq {receiver.recv_seq - 1}: {len(record):>3} bytes on the wire "
              f"-> {delivered!r} verified")
    print("\nnote: this channel authenticates, it does not encrypt (see channel.py)")
    return 0


def cmd_attacks(args: argparse.Namespace) -> int:
    """Run the adversary simulations and summarise."""
    print(_rule("Adversary simulations"))
    results = run_all()
    for result in results:
        print()
        print(result.render())

    # Two of the nine scenarios are controls, not attacks, and neither
    # belongs in the pass count. The honest handshake must succeed, and the
    # unauthenticated-DH machine-in-the-middle must *win* -- that one is the
    # evidence that the tags in the other scenarios are doing the work.
    controls = [r for r in results if "(control)" in r.name]
    attacks = [r for r in results if r not in controls]
    blocked = [r for r in attacks if r.defended]
    unblocked = [r for r in attacks if not r.defended]

    print(_rule("Summary"))
    print(f"{len(blocked)}/{len(attacks)} attacks blocked by AKEX")
    for failure in unblocked:
        print(f"  UNBLOCKED: {failure.name}")

    print(f"\n{len(controls)} controls (excluded from the count above):")
    baseline_ok = all(r.defended for r in controls if "Honest" in r.name)
    mitm_control = next((r for r in controls if "UNAUTHENTICATED" in r.name), None)
    print(f"  honest handshake completed and agreed keys: "
          f"{'yes' if baseline_ok else 'NO -- the protocol itself is broken'}")
    if mitm_control is not None:
        print(f"  the same MITM against unauthenticated DH succeeded: "
              f"{'yes, as expected' if not mitm_control.defended else 'NO -- the control is not working'}")

    return 1 if unblocked else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m akex",
        description="Authenticated Diffie-Hellman key exchange demo.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    handshake = sub.add_parser("handshake", help="run one handshake and use the session")
    handshake.add_argument(
        "--psk", default="example pre-shared key", help="pre-shared key as text"
    )
    handshake.add_argument(
        "--group",
        type=int,
        default=14,
        choices=sorted(GROUPS),
        help="MODP group id (14 = 2048-bit, 15 = 3072-bit)",
    )
    handshake.set_defaults(func=cmd_handshake)

    attacks = sub.add_parser("attacks", help="run every adversary simulation")
    attacks.set_defaults(func=cmd_attacks)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
