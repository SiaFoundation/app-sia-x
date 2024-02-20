# Sia application: Technical specification

This page details the protocol implementation of the Sia app.

## Framework

We use an [APDU protocol](https://gist.github.com/Wollac/49f0c4e318e42f463b8306298dfb4f4a) compatible message format.

All commands use CLA = 0xE0.

| CLA  | INS  | COMMAND_NAME   | DESCRIPTION                             |
| ---- | ---- | -------------- | --------------------------------------- |
| 0xE0 | 0x01 | GET_VERSION    | Returns version of the app              |
| 0xE0 | 0x02 | GET_PUBLIC_KEY | Returns public key or addreses          |
| 0xE0 | 0x03 | SIGN_HASH      | Sign a 32 byte hash                     |
| 0xE0 | 0x04 | GET_TXN_HASH   | Sign a transaction or retrieve its hash |

### Commands requiring multiple messages

Sending a transaction can sometimes take multiple messages if the transaction is sufficiently large.  In the event that more data is required, SW_OK is returned and the app listens for additional messages, which will use P1_MORE=0x80 instead of P1_FIRST=0x00.

### Note on encoding

To learn more on how transactions are encoded, visit https://pkg.go.dev/go.sia.tech/core/types#Transaction.

## Status Words

| SW     | SW Name              | Description                                                                                                                                                                                                                              |
| ------ | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x6B00 | SW_DEVELOPER_ERR     | Errors that should not occur                                                                                                                                                                                                             |
| 0x6B01 | SW_INVALID_PARAM     | Invalid user specified parameters are supplied such as an invalid signature index when signing a transaction                                                                                                                             |
| 0x6B02 | SW_IMPROPER_INIT     | If this is the first packet of a transaction signing event, the transaction context must not already be initialized. Otherwise, an attacker could fool the user by concatenating two transactions.  This error is returned in that case. |
| 0x6985 | SW_USER_REJECTED     | User declined this action                                                                                                                                                                                                                |
| 0x6D00 | SW_INS_NOT_SUPPORTED | Unsupported command used                                                                                                                                                                                                                 |
| 0x9000 | SW_OK                | Success                                                                                                                                                                                                                                  |

## Commands

### GET_VERSION

Returns public keys and addresses.

#### Encoding

##### Command

| CLA  | INS  |
| ---- | ---- |
| 0xE0 | 0x01 |

##### Input data

None

##### Output data

| Length  | Description  |
| ---- | ---- |
| 1 | Major version |
| 1 | Minor version |
| 1 | Maintenance version |

### GET_PUBLIC_KEY

Returns public key or addreses.

#### Encoding

##### Command

| CLA  | INS  | P2
| ---- | ---- | ---- |
| 0xE0 | 0x02 | 0x00 to display address and 0x01 to display pubkey |
 
##### Input data

| Length  | Description  |
| ---- | ---- |
| 4 | Little endian encoded uint32 index |


##### Output data

For pubkey

| Length  | Description  |
| ---- | ---- |
| 32 | Sia-encoded pubkey |

For address

| Length  | Description  |
| ---- | ---- |
| 76 | Sia-encoded address |

### SIGN_HASH

Sign a 32 byte hash.

#### Encoding

##### Command

| CLA  | INS  |
| ---- | ---- |
| 0xE0 | 0x03 | 

##### Input data

| Length  | Description  |
| ---- | ---- |
| 4 | Little endian encoded uint32 index |
| 32 | Binary encoded hash to sign |

##### Output data

| Length  | Description  |
| ---- | ---- |
| 64 | Binary encoded signature |

### GET_TXN_HASH

Sign a transaction or retrieve its hash.

#### Encoding

##### Command

| CLA  | INS  | P1   | P2   |
| ---- | ---- | ---- | ---- |
| 0xE0 | 0x04 | 0x00 for the first message and 0x80 for any messages after | 0x00 to display transaction hash and 0x01 to sign transaction hash |
 
##### Input data

| Length  | Description  |
| ---- | ---- |
| 4 | Little endian encoded uint32 key index |
| 2 | Little endian encoded uint16 signature index |
| 4 | Little endian encoded uint32 change index |
| At most 255-4-2-4=245 bytes | Sia-encoded transaction |

##### Output data

For transaction hash

| Length  | Description  |
| ---- | ---- |
| 32 | Binary encoded transaction hash |

For transaction signature

| Length  | Description  |
| ---- | ---- |
| 64 | Binary encoded transaction signature |
