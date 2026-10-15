# Contributing

Keep the ISO patcher focused on one original Windows ARM64 ISO input and one driver-prepared ISO output. Do not reintroduce disk writers, Pi firmware, custom setup programs or diagnostic user interfaces.

Preserve exact-profile patch guards, signing checks, input immutability, private-key exclusion, Microsoft Setup and all original Windows editions. Add focused synthetic regression coverage for image or driver changes. Public CI must never receive original Windows images, user drivers, private input archives or hardware logs.

Linux checks: `python -m unittest -v test_pi5_nvme_tool`, `python -m unittest discover -s tests -v`, and `python tools/verify_source.py`. Native image tests require the packages listed in the desktop workflow. The GUI is rendered offscreen in ARM64 and x64 Linux CI. Checks are software validation, not physical boot evidence.

Refresh SOURCE_MANIFEST.json after reviewed source changes. Retain the original license and attribution. Publish source and application assets only; users generate their Windows-derived ISO locally.
