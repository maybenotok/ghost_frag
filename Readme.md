# Ghost Frag

![[ghost_frag.png]]

Bypass of the [CVE-2026-43500](https://security-tracker.debian.org/tracker/CVE-2026-43500)
patch. `__pskb_copy_fclone()` does not propagate `SKBFL_SHARED_FRAG`,
allowing page-cache writes through rxkad in-place decrypt.

Ghost Frag is basically just Dirty Frag with modifications.

![[poc.png]]

PoC developed on 18 May. I reported the issue, but was informed that it had already been reported. I should have checked lore.kernel.org first.

https://lore.kernel.org/netdev/ageeJfJHwgzmKXbh@v4bel/