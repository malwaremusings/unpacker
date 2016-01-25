# unpacker
WinAppDbg script to automate malware unpacking.

## Features
- Detects certain unpacking behaviour (but not all)
  - Determines original entry point
    - Determines jump point to original entry point
  - Dumps unpacked code to a file
  - Attempts to find unpacking loop
- Dumps memory decrypted by CryptDecrypt()
- Dumps memory decompressed by RtlDecompressBuffer()
- Attempts to detect process hollowing
  - Dumps injected memory blocks to a file
- Dumps decrypted network traffic

## More information
[Automated Unpacking: A Behaviour Based Approach](http://malwaremusings.com/2013/02/26/automated-unpacking-a-behaviour-based-approach/)

[Beyond Automated Unpacking: Extracting Decrypted/Decompressed Memory Blocks](http://malwaremusings.com/2014/09/16/beyond-automated-unpacking-extracting-decrypteddecompressed-memory-blocks/)
