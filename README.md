# nanos-app-sia

This is the official Sia wallet app for the Ledger Nano S.

This code is unpolished and may contain bugs. However, it is feature-complete:
you can generate Sia addresses, calculate transaction hashes, sign those
hashes, and use those signatures to construct valid transactions. The Sia app
is the most secure method currently available for performing these actions.

No binaries are provided at this time. To build and install the Sia app on
your Ledger Nano S, follow Ledger's [setup instructions](https://ledger.readthedocs.io/en/latest/userspace/getting_started.html).

After the app is installed, use the `getPublicKey.py`, `signTxn.py`, and
`signHash.py` scripts to interact with the device, and `txn2bin.go` to convert
a JSON-encoded transaction to binary for use with `signTxn.py`.

## Security Model

The attack surface for using the Sia wallet app on a Ledger Nano S comprises
the Sia app itself, the system firmware running on the Nano S, the computer
that the Nano S is connected to, and posession/control of the device. For our
purposes, the app only needs to ensure its own correctness and protect the
user from the computer that the Nano S is connected to. Other attack surfaces
are beyond our control; we assume that the user physically controls the
device, is not running malicious/buggy software on the device, and follows
proper security protocols. The goal of the Sia app is to achieve perfect
security given these assumptions.

The main attack vector that we are concerned with, then, is a computer running
malicious sofware. This software may imitate scripts like `getPublicKey.py`,
`signTxn.py`, etc. in such a way that the user cannot tell the difference, but
secretly act maliciously. Specifically, the computer can do the following:

1. Lie to the user about which actions it is performing. *Example: the user
   runs `./signTxn foo.txn`, but the computer secretly runs `./signTxn bar.txn`
   instead.*
2. Lie to the user about what it received from the Nano S. *Example: the Nano
   S generates address X, but the computer displays address Y.*
3. Exfiltrate data supplied by the user or the Nano S. *Example: the user
   generates addresses A and B; the computer "phones home" to report that A and
   B are owned by the same person.*
4. Refuse to comply with the user's requests. *Example: the user runs
   `./signTxn foo.txn`, but the computer does nothing.*

Clearly the app cannot prevent the computer from performing type-3 or type-4
actions. Fortunately, these actions do not allow the attacker to steal coins;
they can only gather metadata and temporarily prevent the user from performing
certain actions. Type-1 and type-2 actions, on the other hand, are much more
dangerous, and can be trivially exploited to steal the user's coins. To combat
these attacks, apps must make use of the embedded display on the Nano S. If
data sent to/from the Nano S is displayed on the screen, the user can verify
that the computer is not lying about what it sent or received. In the interest
of user-friendliness, we would like to display as little information as much
as possible, but each omission brings with it the risk of introducing a
vulnerability. Therefore, an app should display all data by default, and omit
data only after subjecting the omission to extreme scrutiny. The Sia app
adheres to this principle more closely than most Ledger apps, and as a result
is not affected by certain vulnerabilities affecting those apps.


## Full keygen + signing example

This walkthrough will demonstrate how to generate addresses and sign
transactions on a Ledger Nano S. As long as you trust the Ledger firmware and
follow proper security procedures, this is currently the safest known way of
sending and receiving siacoins. Failure to follow proper security procedures
will make this method less secure, but it still has much smaller attack
surface than alternative methods.

To begin, install the app on your Ledger Nano S, open it, and run the
`getPublicKey.py` script on your computer. This will generate a public key for
index 0, and its associated Sia address for a specific set of unlock
conditions, which we will use later. You can now receive coins at this
address. To generate a different address, set the `--index` argument to
`getPublicKey.py` appropriately. Make note of the index you used, because you
will need it in order to spend any coins stored in that address.

Possible attacks at this point:

- The computer could display a different address on its screen than the one
  that appears on the device, tricking you into sending coins to an attacker-
  controlled address. Make sure to compare the displayed addresses.

- The computer could display a different public key on its screen than the
  one that appears on the device. If this public key is used in custom unlock
  conditions, it could be difficult (likely impossible) to spend the coins
  sent to the corresponding address. Pass the `--pubkey` flag to
  `getPublicKey.py` to make the device display the public key instead of the
  address. Unfortunately, the font used by the Nano S make it impossible to
  distinguish between the 'l' and 'I' characters. For maximum security, keep
  incrementing the key index until the resulting key does not contain either
  character.

- The computer could secretly send a different key index to the device than
  the one you specified, making it difficult (likely impossible) to spend the
  coins later. Make sure to compare the displayed indexes.

Let's assume that you generated the following public key and address:

```
Public key: 5GhilFqVBKtSCedCZc6TIthzxvyBH9gPqqf+Z9hsfBo=
Address:    996b3fc7de889073b1fffcaa52c18c447cbcf4f6d7825e16e88b73d2ae1aa74cbd96f1f1699f
```

Sending coins to this address creates a Siacoin Output that you can spend
later. You can find these IDs by searching for the address on a public
explorer or by importing the address into a `siad` wallet. Let's assume that
you sent 10 SC to the address. You can find the ID of this output by using the
`/wallet/unspent` endpoint:

```
$ curl -A "Sia-Agent" localhost:9980/wallet/unspent
{
  "outputs": [{
    "id": "48dcaacaf0ecb0ffce702b9115365e52b3cacc01ae87a70d8ca47349fbdc6830",
    "fundtype": "siacoin output",
    "unlockhash": "996b3fc7de889073b1fffcaa52c18c447cbcf4f6d7825e16e88b73d2ae1aa74cbd96f1f1699f",
    "value":"10000000000000000000000000",
    "confirmationheight": 162875
  }]
}
```

You will also need the unlock conditions for the address, which are:

```json
{
  "timelock": 0,
  "publickeys": [{
    "algorithm": "ed25519",
    "key":"5GhilFqVBKtSCedCZc6TIthzxvyBH9gPqqf+Z9hsfBo="
  }],
  "signaturesrequired": 1
}
```

If you use the public key to construct more complicated unlock conditions
(such as a multisig scheme), make sure you write down the unlock conditions
somewhere, and use the `--pubkey` flag so that the device displays the public
key instead of the address.

Now you can construct a transaction that spends these coins. Let's create a
transaction that sends 5 SC to a friend, pays a 1 SC miner fee, and returns
the rest to us:

```json
{
  "siacoininputs": [{
    "parentid": "48dcaacaf0ecb0ffce702b9115365e52b3cacc01ae87a70d8ca47349fbdc6830",
    "unlockconditions": {
      "timelock": 0,
      "publickeys": [{
        "algorithm": "ed25519",
        "key": "5GhilFqVBKtSCedCZc6TIthzxvyBH9gPqqf+Z9hsfBo="
      }],
      "signaturesrequired": 1
    }
  }],
  "siacoinoutputs": [
    {
      "value": "5000000000000000000000000",
      "unlockhash": "17d25299caeccaa7d1598751f239dd47570d148bb08658e596112d917dfa6bc8400b44f239bb"
    },
    {
      "value": "4000000000000000000000000",
      "unlockhash": "996b3fc7de889073b1fffcaa52c18c447cbcf4f6d7825e16e88b73d2ae1aa74cbd96f1f1699f"
    }
  ],
  "minerfees": ["1000000000000000000000000"],
  "transactionsignatures": [{
    "parentid": "48dcaacaf0ecb0ffce702b9115365e52b3cacc01ae87a70d8ca47349fbdc6830",
    "publickeyindex": 0,
    "coveredfields": { "wholetransaction": true }
  }]
}
```

Save this as `txn.json` and run `./txn2bin txn.json txn.bin`. This will
convert the JSON transaction to a binary format that the Ledger understands.

To sign the transaction, we pass the binary transaction to the Ledger Nano S using the
`signTxn.py` script:

```
$ ./signTxn.py txn.bin 0 --index 0
Signature: QQcC9sCIbY/59CixDBJAyF4JgeGLlrYyhSgSbAMVuUW2YAIKPfzmWSWS9/vcppNTJV46H1Y+fImAMDeGzFVtAg==
```

Here, the `0` argument means we are creating a signature for the 0th element
in the `transactionsignatures` array. Unlike `./getPublicKey.py`, we must
explictly set `--index 0` to specify that we are signing with key 0.

Possible attacks at this point:

- The computer could send a different transaction to the device than the one
  you specified. Make sure to compare each element of the transaction to
  `txn.json`.

- The computer could secretly send a different key index than the one you
  specified. This would result in an invalid signature. Coins could not be
  stolen this way, but the attacker could prevent you from creating a valid
  transaction. Make sure to compare the displayed indexes.

- The computer could display a different signature on its screen than the one
  actually sent by the device. As in the previous attack, this would merely
  result in an invalid signature.

Finally, we can append the signature to the transaction:

```diff
   "transactionsignatures": [{
+    "signature": "QQcC9sCIbY/59CixDBJAyF4JgeGLlrYyhSgSbAMVuUW2YAIKPfzmWSWS9/vcppNTJV46H1Y+fImAMDeGzFVtAg==",
     "parentid": "48dcaacaf0ecb0ffce702b9115365e52b3cacc01ae87a70d8ca47349fbdc6830",
     "publickeyindex": 0,
     "coveredfields": { "wholetransaction": true }
   }]
```

The transaction is now valid, and can be broadcast using the `siac wallet
broadcast` command, or by posting directly to the `/tpool/raw` endpoint:

```
$ siac wallet broadcast "$(<txn.json)"
Transaction broadcast successfully
```
