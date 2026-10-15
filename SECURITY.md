# Security and private inputs

Do not commit Windows ISOs, WIM/ESD images, driver originals, generated driver packages, certificates/private keys, private input archives or personal hardware logs. The source manifest forbids these file types in release source snapshots.

The builder works on local copies without mounting host disks or changing host registry/certificate stores. Existing source/output files cannot be overwritten. Exact driver hashes and patch profiles are mandatory. Local test signing requires Secure Boot to be off in the eventual Windows environment; externally generated boot configuration must be assessed separately.

Build logs stay local. Review any report before sharing it; filenames and device-specific information can be private. Never include private signing keys in an issue or CI artifact.
