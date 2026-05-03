## Review Request: Full Bitcoin Stack Support & SDK Enhancements

### Changes
- **AssetRegistry**: Added  and  to the  enum and registered their native BTC assets ( for RSK,  for BOB).
- **BitcoinManager**: Introduced a new module leveraging BDK for descriptor-based wallet management (SegWit/Taproot).
- **TaprootManager**: Enhanced with  and improved integration with .
- **Unit Tests**: Added  and  to verify the new functionality.

### Verification
- Ran `cargo test` and verified that all 33 tests pass, specifically the new RSK/BOB and BitcoinManager tests.
