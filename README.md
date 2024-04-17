# MSF HTTP Brute Forcer Module

The `auxiliary/scanner/http/http_bruteforcer.rb` is a Metasploit module designed to perform multi-threaded HTTP brute force attacks.

## Features

- **Flexible Injection Points**: Set the brute force point anywhere in the body of a POST request, in the URL, or in the cookies. Use the `^INJECTION^` marker in the settings variables `DATA`, `TARGETURI`, or `COOKIE` to indicate where the injection should occur.
- **Dictionary-Based Attacks**: The brute force attack relies on a dictionary of words, one per line, specified by the full path in the `INJECTION_FILE` setting.
- **Response Handling**: Define HTTP response codes to interpret as failure or success (`FAILURE_HTTP_CODE`, `SUCCESS_HTTP_CODE`). If no response is received or if the response code is listed in `RETRY_HTTP_CODE`, the same keyword will be attempted again.
- **Retry Logic**: Use the `RETRIES` setting to specify the number of consecutive failures before giving up.
- **Threading**: The `THREADS` setting allows for the specification of concurrent threads, significantly dividing the run time depending on the machine's ability to handle the load. A high value can potentially overload the target and create a denial of service.
- **Controlled Speed**: `BRUTEFORCE_SPEED` sets a delay in milliseconds between attempts, useful in scenarios where a slower, more deliberate approach is required.
- **Verbosity Levels**:
  - `0`: No output.
  - `1`: Silent except on pressing ENTER, which shows the latest attempt (recommended for production).
  - `2`: Displays all attempts.

Successful keywords will be stored in the MSF credentials list with, or in the MSF notes.

## Installation

1. Copy the file `http_bruteforcer.rb` to your local Metasploit directory, typically located at `/usr/share/metasploit-framework/modules/auxiliary/scanner/http/`.
2. If `msfconsole` is already running, type `reload_all`. Otherwise, start `msfconsole`.
3. Use the command `use auxiliary/scanner/http/http_bruteforcer` to load the module and set up the options.
4. Ensure the MSF database is running with `msfdb start`.

## Usage

This module is versatile:
- **Directory Brute Forcing**: Set the injection point in the URI specified in the `TARGETURI` setting.
- **Credential Guessing**: This module comes to offer more flexibility than "HTTP Login Utility" provided by hdm <x@hdm.io>, by providing true multi-threading, which is beneficial for extensive brute force attacks on a single target.
- **DDoS**: This module can be used as well to load heavy endpoints in bulk and create denial of service.

## Useful Links

- Wordlist dictionaries: [SecLists on GitHub](https://github.com/danielmiessler/SecLists/tree/master)
