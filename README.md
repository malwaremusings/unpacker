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

## File hashes
I'm testing a mechanism for verifying the integrity of my code downloaded from GitHub by storing the file hashes in my DNS zone. This has the advantage of preventing (or lessening the chance of) an attacker being able to modify the code and also modify the corresponding hashes.

To get the SHA256 hash for the zip download file (I'm only doing the zip downloads at the moment, because I have to enter all of this information manually), issue a DNS request for the TXT record <zipfile name>.sha256.malwaremusings.com.

For instance, to obtain the SHA256 hash for unpacker-master.zip, issue a DNS TXT record request for unpacker-master.sha256.malwaremusings.com.
