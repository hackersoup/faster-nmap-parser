
# About
Gnmap parser is slow because of how many times it reparses the file.
It is also inaccurate because it uses the deprecated gnmap files instead of the recommended XML files.
This solves all three of those problems.

# Install

On Debian / Ubuntu / Kali:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
cargo install --branch main --git https://github.com/hackersoup/faster-nmap-parser
```

# Run

`faster-nmap-parser <nmap xml file>`