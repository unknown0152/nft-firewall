You are working on my NFT Firewall project, branch v12.1-smartops-safety.

Goal: implement V12.1 SmartOps Safety Layer.

Focus only on:
- fw wrapper command
- fw doctor
- fw safe-apply
- shared IP/CIDR validation
- never_block protection
- persistent dynamic nft sets
- least-privilege sudoers wrappers
- safer setup
- tests

Hard rules:
- Do not weaken VPN killswitch logic.
- Do not remove SSH safety protections.
- Do not apply live firewall rules without explicit user approval.
- Do not use broad sudoers wildcards.
- Always run nft --check before any apply.
- Keep changes reviewable in git.
