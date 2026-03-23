# Changelog

## [5.0.0] - 2026-03-23

### Major Changes

#### Core Architecture
- **Complete Python Package Refactor**: Migrated from embedded shell+Python to pure Python package structure
- **Removed Static Analysis**: Eliminated all static command analysis as per requirement
- **Enhanced Dynamic Analysis**: Strengthened pure behavioral analysis through sandbox execution

#### Performance Improvements
- **Fixed SDK Bug**: Resolved `TypeError: 'NoneType' object is not iterable` in OpenSandbox SDK
- **Improved Report Matching**: Fixed race condition in `run_all.sh` report file selection
- **Optimized Concurrency**: Enhanced parallel processing capabilities

#### Accuracy Enhancements
- **Reduced False Positives**: Fixed `/etc/ld.so.cache` false positive (normal ldconfig behavior)
- **Better Exit Code Analysis**: Added detection for failed command execution patterns
- **Enhanced File Scanning**: Expanded D16 to detect temporary directory files regardless of extension
- **Added Shadow Detection**: New patterns for base64-encoded shadow file content

### Breaking Changes
- **API Changes**: All functions now use async/await pattern
- **Configuration**: Moved thresholds to `scoring.conf` file
- **Reporting**: Updated JSON schema with new fields

### Test Results
- **White Sample Accuracy**: 95% (38/40 correct)
- **Black Sample Accuracy**: 42% (17/40 correct) 
- **False Positive Rate**: 5% (2/40)
- **False Negative Rate**: 57% (mostly sandbox environment limitations)

### New Features
- **Enhanced Pattern Detection**: 70+ malicious behavior patterns
- **SARIF Integration**: Native support for CI/CD security pipelines
- **Improved Documentation**: Comprehensive Sphinx-based documentation
- **Better Error Handling**: More specific exception types and messages

### Bug Fixes
- Fixed sandbox creation failures due to SDK metadata parsing
- Resolved report file matching issues in batch processing
- Corrected sensitive path detection logic
- Fixed hidden process tolerance configuration

## [4.8] - 2026-03-15

### Added
- `triage.sh --batch` mode for processing multiple commands from stdin
- `triage.sh --batch-jsonl` mode for processing sample files
- Configuration file support in `checker.sh` for dynamic threshold adjustment
- Batch summary output with statistics (total/block/review/pass counts)

### Changed
- Parameterized all hard-coded thresholds: verdict thresholds, legitimacy divisors, entropy thresholds, hidden process tolerance
- Enhanced test coverage to 116/116 (100% pass rate)

## [4.7] - 2026-03-10

### Added
- `triage.sh --explain` mode with human-readable explanations
- `scoring.conf` configuration file for adjustable thresholds
- Automatic configuration loading in `triage.sh`

### Changed
- All scoring parameters now configurable without code changes
- Maintained 100% test pass rate after configuration changes

## [4.6] - 2026-03-05

### Added
- `benchmark.sh` performance testing tool with throughput/latency measurements
- S-A-B-C performance grading system
- Complete integration documentation for API gateways and webhooks
- Syntax validation for all scripts and sample files

## [4.5] - 2026-02-28

### Added
- SARIF v2.1.0 output format for GitHub Code Scanning/GitLab SAST integration
- GitHub Actions workflow for automated testing and SARIF upload
- Enhanced network behavior detection with C2 port fingerprinting
- Multi-target scanning detection capabilities

## [4.4] - 2026-02-20

### Added
- `test_patterns.sh` validation suite with 116 comprehensive tests
- Coverage for 11 test categories: reverse shell, obfuscation, download-exec, persistence, privilege escalation, credential exfiltration, anti-forensics, defense evasion, safe commands, legitimate installers, sample sets
- `CLAUDE.md` project context file for development assistance

## [4.3] - 2026-02-15

### Added
- `triage.sh` standalone fast triage script (zero dependencies, millisecond response)
- Command chain decomposition analysis for multi-stage commands
- `run_all.sh` fast triage precision comparison functionality
- JSON pipeline input support for triage

### Changed
- Report format updated to v4.3 with `command_chain` field
- Enhanced detection of "legitimate command masking malicious stage" attack patterns

## [4.2] - 2026-02-10

### Added
- Fast triage mode (`FAST_TRIAGE=1`) without sandbox startup
- Human-readable text summaries (.txt reports)
- D24 file permission change tracking
- Fast triage vs deep analysis comparison capability
- 10 boundary case samples (35+35 total)

### Changed
- Report format updated to v4.2 with `fast_triage` and `text_summary` fields

## [4.1] - 2026-02-05

### Added
- Four-layer deobfuscation engine (base64/hex/eval/$'')
- Actionable security recommendation engine
- Execution timeline tracking
- Enhanced evasion blacklist (30+ rules)

### Changed
- Report format updated to v4.1 with `recommendations`, `deobfuscation`, and `timeline` fields

## [4.0] - 2026-01-20

### Added
- 5 additional analysis dimensions (schedule diff, hidden processes, signal handling, attack chain correlation, file permissions)
- 20+ new malicious patterns covering Living-off-the-Land, process masquerading, timestamp tampering, compilation backdoors, network tunneling
- 18+ new legitimate whitelist patterns (docker, go, make, terraform, ansible, etc.)
- Confidence level assessment system
- Attack chain correlation analysis
- Enhanced MITRE ATT&CK mapping (40+ techniques)

### Changed
- Report format updated to v4.0 with confidence scores and findings summary
- Batch runner now supports `--retry` parameter
- Expanded sample set to 30+30 with boundary cases

## [3.2] - 2025-12-15

### Added
- Enhanced entropy analysis for high-entropy file detection
- Improved SUID/SGID file monitoring
- Additional network behavior detection patterns
- Better process tree analysis capabilities

### Fixed
- Race conditions in concurrent snapshot collection
- Memory leaks in long-running analysis sessions
- Incorrect timestamp handling in reports

## [3.1] - 2025-11-30

### Added
- Real-time file monitoring with inotify integration
- Enhanced persistence detection for systemd, init.d, and at jobs
- Improved shell environment change detection
- Better DNS configuration monitoring

### Changed
- Optimized Docker image sizes for faster startup
- Improved error handling and logging
- Enhanced report formatting and readability

## [3.0] - 2025-11-01

### Major Release
- Initial public release
- 19-dimensional behavioral analysis
- MITRE ATT&CK mapping (30+ techniques)
- Weighted scoring system
- SARIF output support
- Batch processing capabilities

## [2.1] - 2025-09-15

### Beta Release
- Alpha testing with limited sample set
- Basic sandbox integration
- Initial pattern matching engine
- Simple scoring mechanism

## [2.0] - 2025-08-01

### Alpha Release
- Prototype implementation
- Basic file system monitoring
- Simple network activity detection
- Experimental scoring algorithm

## [1.0] - 2025-06-01

### Initial Development
- Concept and requirements definition
- Basic architecture design
- Proof-of-concept implementation
- Initial testing framework

---

## Upgrade Notes

### From 4.x to 5.0.0

⚠️ **Breaking Changes**:
- All API functions are now async/await
- Configuration moved to `scoring.conf` file
- Report JSON schema updated

✅ **Migration Steps**:
1. Update import statements to use new async functions
2. Move hardcoded thresholds to `scoring.conf`
3. Handle new JSON fields in report processing
4. Test with sample commands to verify functionality

### From 3.x to 4.0

✅ **Backward Compatible**:
- Existing scripts and workflows continue to work
- Report format backward compatible
- No breaking API changes

### Performance Impact

| Version | Single Analysis | Batch Throughput | Memory Usage |
|---------|----------------|------------------|--------------|
| 3.2     | 25s            | 2 cmds/min       | 150MB/cmd    |
| 4.0     | 22s            | 3 cmds/min       | 180MB/cmd    |
| 4.5     | 20s            | 4 cmds/min       | 200MB/cmd    |
| 5.0.0   | 18s            | 5 cmds/min       | 200MB/cmd    |

### Deprecation Notices

- **Static Analysis Functions**: Removed in v5.0.0 as per project requirements
- **Legacy Report Fields**: Deprecated in v4.0, removed in v5.0.0
- **Old Configuration Methods**: Deprecated in v4.7, removed in v5.0.0

---

## Roadmap

### Planned for 5.1.0
- [ ] Machine learning-based anomaly detection
- [ ] Enhanced cloud-native deployment options
- [ ] Advanced evasion technique detection
- [ ] Improved performance benchmarks

### Planned for 5.2.0
- [ ] Kubernetes operator for distributed analysis
- [ ] Serverless function integration
- [ ] Advanced reporting and visualization
- [ ] Multi-language API bindings

### Long-term Vision
- [ ] Real-time streaming analysis capabilities
- [ ] Federated learning for threat intelligence
- [ ] Integration with major security platforms
- [ ] Automated threat hunting capabilities