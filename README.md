# This repo has been deprecated!

Moved to https://github.com/HathorNetwork/hathor-ledger-app

# ledger-app-hathor

This is the official Hathor wallet app for the Ledger Nano S.

It allows you to generate addresses and sign transactions. The Hathor app is the most secure method
currently available for performing these actions.

Use it with our official desktop wallet (https://github.com/HathorNetwork/hathor-wallet).

## Setup environment

To build and install the Hathor app on your Ledger Nano S, follow Ledger's [setup instructions](https://ledger.readthedocs.io/en/latest/userspace/getting_started.html).

### Tips

Some recommendations for setting up the environment (tested on Ubuntu 18.04 on VirtualBox):
- use the exact same versions indicated on the guide, even though they are a bit outdated (`gcc-arm-none-eabi-5_3-2016q1` and `clang-7.0.0`).
- adjust udev rules following https://support.ledger.com/hc/en-us/articles/115005165269-Fix-connection-issues
