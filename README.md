# nanos-app-sia

This is the official Sia wallet app for the Ledger Nano S.

This code is unpolished and lacking in functionality. However, it is minimally
viable: you can generate Sia addresses and sign hashes, and use the addresses
and signatures to construct valid transactions. The primary deficiency is that
the hash must be trusted; you should only sign a hash if you trust that it was
computed correctly. **DO NOT** trust someone else's computer (or worse, a
website) to compute hashes for you.

No binaries are provided at this time. To build and install the Sia app on
your Ledger Nano S, follow Ledger's [setup instructions](https://ledger.readthedocs.io/en/latest/userspace/getting_started.html).

After the app is installed, use the `getPublicKey.py` and `signHash.py`
scripts to interact with the device, and `txnSigHash.go` to compute the hash
of a JSON-encoded transaction.


## Full keygen + signing example

This walkthrough will demonstrate how to generate addresses and sign
transactions on a Ledger Nano S. Until the app is completed, this process will
not be considered fully secure; if you are actively targeted by an attacker,
there are known methods they could use to steal your coins. Still, using the
app is probably more secure than existing alternatives.

To begin, install the app on your Ledger Nano S, open it, and run the
`getPublicKey.py` script on your computer. This will generate a public key for
index 0 and its associated Sia address for a specific set of unlock
conditions, which we will use later. You can now receive coins at this
address. To generate a different address, set the `--index` argument to
`getPublicKey.py` appropriately. Make note of the index you used, because you
will need it in order to spend any coins stored in that address.

Possible attacks at this point:

- An attacker could display a different address on the computer than the one
  that appears on the device, tricking you into sending coins to an attacker-
  controlled address. Make sure to compare the displayed addresses.

- An attacker could display a different public key on the computer than the
  one that appears on the device, making it difficult (likely impossible) to
  spend the coins later. Pass the `--pubkey` flag to `getPublicKey.py` to make
  the device display the public key instead of the address.

- An attacker could secretly send a different key index to the device than
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
somewhere.

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

Save this as `txn.json` and run `go run txnSigHash.go 0 txn.json`. This will
print the hash of the fields covered by the transaction signature:
```
bfa1990672469b3b744e15082c3b3ba610996c1902f6b7d010857b907cdd84df
```

To sign the transaction, we pass this hash to the Ledger Nano S using the
`signHash.py` script:

```
$ ./signHash.py bfa1990672469b3b744e15082c3b3ba610996c1902f6b7d010857b907cdd84df
Signature: 2kWyf9e1uOXCyoH8+gu/AqH4876k8SuRMq+dwgoMf3burpkXV++qyDzMnKmZavPdvjmbH1uL1Glzq6juNunMDA==
```

As before, index 0 is used by default; set the `--index` argument to specify a
different index. After approving the signature on the device, the signature
will be displayed on the computer.

Possible attacks at this point:

- An attacker could display a different hash on the computer than the one that
  appears on the device, tricking you into signing a different transaction,
  e.g. a transaction that sends your coins to the attacker. Make sure to
  compare the displayed hashes.

- An attacker could display a different hash than the actual transaction hash
  (e.g. by replacing `txnSigHash.go` with a malicious program, or by rewriting
  the contents of `txn.json`). It is imperative that you only sign hashes that
  you trust were computed correctly. In practice it is difficult (likely
  impossible) to compute hashes in a fully-trusted way. This is currently the
  biggest weakness in the Sia app, and must be addressed before the official
  release.

- An attacker could secretly send a different key index than the one you
  specified. This would result in an invalid signature. Coins could not be
  stolen this way, but the attacker could prevent you from creating a
  transaction. Make sure to compare the displayed indexes.

- An attacker could display a different signature than the one actually sent
  by the device. As in the previous attack, this would merely result in an
  invalid signature.

Finally, we can append the signature to the transaction:

```diff
  "transactionsignatures": [{
    "parentid": "48dcaacaf0ecb0ffce702b9115365e52b3cacc01ae87a70d8ca47349fbdc6830",
    "publickeyindex": 0,
-    "coveredfields": { "wholetransaction": true }
+    "coveredfields": { "wholetransaction": true },
+    "signature": "2kWyf9e1uOXCyoH8+gu/AqH4876k8SuRMq+dwgoMf3burpkXV++qyDzMnKmZavPdvjmbH1uL1Glzq6juNunMDA=="
  }]
```

The transaction is now valid, and can be broadcast using the `siac wallet
broadcast` command, or by posting directly to the `/tpool/raw` endpoint:

```
$ siac wallet broadcast "$(<txn.json)"
Transaction broadcast successfully
```
