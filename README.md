# GOBip352

This library provides the basic functions for working with BIP352.
It takes care of the elliptic curve computations and some periphery around creating outputs and scanning.
This library is not a full wallet. For example the current scope does not include checking whether inputs are eligible
as [Inputs For Shared Secret Derivation](https://github.com/josibake/bips/blob/silent-payments-bip/bip-0352.mediawiki#inputs-for-shared-secret-derivation).


## Todo

### Priority 1
- [x] Sending vectors passing
- [x] Receiving vectors passing
- [x] Include vin checking module (include functionality that allows for checking whether inputs are eligible according to the BIP)
  - should be on par with the reference implementation now

### Priority 2
- [x] Consider using fixed length byte arrays instead of slice, will help with "type-safety" of keys, hashes, compressed, x-only, scalars
- [x] Standardize errors as types
- [ ] Benchmark a map of labels against looping over the slice of labels in matching 