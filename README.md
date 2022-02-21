# sbom-utility

Initially, we want to validate SPDX or CycloneDX SBOMs (JSON format only) to current standard schema.

Specifically, we want to parse standardized SBOM output from tooling, validate it using the declared schema format (e.g., SPDX, CycloenDX) and version (e.g., "2.2", "1.3", etc.) with the goal of being able to losslessly convert it to the most current other formats to CycloneDX schema (normative) for comparison. Once this is accomplished we wish to support "merge" operations (with deduplication if possible) of multiple CycloneDX SBOMs produced from a plurarlity of tool sources.

---

### Installation

Since the utility comes with a default configuration file and input schemas ready-mde for both SPDX and CycloneDX validation, the best way to install it is to
clone the entirety of the repository at this time.   Over time, we hope to be able to create a release process for the binary with just the necessary supporting files, but at this time achieving the validation function is tactically important.

```bash

```

### Building

### Running

### Supporting new SBOM formats and schema versions


---

## References

- https://github.com/spdx
- https://tools.spdx.org/app/convert/ - Used this to convert from tv format to json
  - NOTE: tool could not convert `example6-bin.spdx`; resulted in an error

---

## Testing

### Authoring

As the actual tests files, `config.json` as well as the schema definition files are loaded relative to the project root, you will need to assure you change the working directory when initializing any `_test.go` module. For example, in `cmd/validate_test.go` file, you would need to change the working directory one level back:

```go
// Need to change the working directory to the application root instead of
// the "cmd" directory where this "_test" file runs so that all test files
// as well as "config.json" and its referenced JSON schema files load properly.
wd, _ := os.Getwd()
last := strings.LastIndex(wd, "/")
os.Chdir(wd[:last])
```

### Running

Example: running test on the `cmd` package:

```sh
go test github.com/mrutkows/sbom-utility/cmd -v
```

run an individual test within the `cmd` package:

```sh
go test github.com/mrutkows/sbom-utility/cmd -v -run TestCDX13MinRequiredVariantIBM
```

## Tooling

### VSCode debugging

In order to see global variables while debugging a specific configuration, you can add the `"showGlobalVariables": true` to it within your `launch.json` config. file:

```json
        {
            "showGlobalVariables": true,
            "name": "Test name",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "main.go",
            "args": ["validate", "-i", "test/cyclonedx/cdx-1-3-min-required.json","-t"]
        },
```

or add it globally to the `settings.json` file:

1. Use `Command-Shift-P` to open `settings.json`
2. Select "Preferences: Open Settings (JSON)"
3. Add the following block at the top level:

```json
"go.delveConfig": {
    "showGlobalVariables": true
},
```

_Please note that this setting was only recently disabled by default as a stop-gap measure due to performance (loading) problems under Windows._
