# ledger-app-sia-x

This is a Sia wallet app for the Ledger Stax, Nano S, Nano SP, and Nano X.

When installed on a Ledger device, the app allows you to generate Sia addresses,
calculate transaction hashes, sign those hashes, and use those signatures to
construct valid transactions. The Sia app is the most secure method currently
available for performing these actions.

This code also serves as a walkthrough for writing your own Ledger device.
The code is heavily commented and describes both the high-level architecture
and low-level implementation details of Ledger app development. Begin by
reading `src/main.c`, and the comments will tell you which files to read next.

No binaries are provided at this time. To build and install the Sia app on
your Ledger device, follow Ledger's [setup instructions](https://speculos.ledger.com/user/docker.html).

After the app is installed, build the `sialedger.go` binary to interact with
the device. `./sialedger --help` will print a list of commands.

## Installation and Usage

Please refer to our [standalone guide](https://docs.sia.tech/sia-integrations/using-the-sia-ledger-nano-app-sia-central) for a walkthrough that demonstrates how
to install the app, generate addresses and sign transactions.

## Security Model

The attack surface for using the Sia wallet app on a Ledger device comprises
the Sia app itself, the system firmware running on the Ledger device, the computer
that the Ledger device is connected to, and possession/control of the device. For our
purposes, the app only needs to ensure its own correctness and protect the
user from the computer that the Ledger device is connected to. Other attack surfaces
are beyond our control; we assume that the user physically controls the
device, is not running malicious/buggy software on the device, and follows
proper security protocols. The goal of the Sia app is to achieve perfect
security given these assumptions.

The main attack vector that we are concerned with, then, is a computer running
malicious software. This software may imitate programs like `sialedger` in such
a way that the user cannot tell the difference, but secretly act maliciously.
Specifically, the computer can do the following:

1. Lie to the user about which actions it is performing. *Example: the user
   runs `./sialedger addr 1`, but the computer secretly runs `./sialedger addr 2`
   instead.*
2. Lie to the user about what it received from the Ledger device. *Example: the Nano
   S generates address X, but the computer displays address Y.*
3. Exfiltrate data supplied by the user or the Ledger device. *Example: the user
   generates addresses A and B; the computer "phones home" to report that A and
   B are owned by the same person.*
4. Refuse to comply with the user's requests. *Example: the user runs
   `./sialedger addr 1`, but the computer does nothing.*

Clearly the app cannot prevent the computer from performing type-3 or type-4
actions. Fortunately, these actions do not allow the attacker to steal coins;
they can only gather metadata and temporarily prevent the user from performing
certain actions. Type-1 and type-2 actions, on the other hand, are much more
dangerous, and can be trivially exploited to steal the user's coins.

To combat these attacks, apps must make use of the embedded display on the
Ledger device. If data sent to/from the Ledger device is displayed on the screen, the user
can verify that the computer is not lying about what it sent or received. In
the interest of user-friendliness, we would like to display as little
information as much as possible, but each omission brings with it the risk of
introducing a vulnerability. Therefore, an app should display all data by
default, and omit data only after subjecting the omission to extreme scrutiny.
The Sia app adheres to this principle more closely than most Ledger apps, and
as a result is not affected by certain vulnerabilities affecting those apps.
