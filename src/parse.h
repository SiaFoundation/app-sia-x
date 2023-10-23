#ifndef PARSE_H
#define PARSE_H

int cur2dec(uint8_t *out, uint8_t *cur);
void need_at_least(txn_state_t *txn, uint64_t n);
void seek(txn_state_t *txn, uint64_t n);

uint8_t readUint8(txn_state_t *txn);
uint64_t readInt(txn_state_t *txn);
void readCurrency(txn_state_t *txn, uint8_t *outVal);
void readHash(txn_state_t *txn, char *outAddr);
void readPrefixedBytes(txn_state_t *txn);
void readUnlockConditions(txn_state_t *txn);
void readCoveredFields(txn_state_t *txn);

#endif /* PARSE_H */