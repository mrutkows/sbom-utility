# sbom-utility

Initially, we want to validate SPDX or CycloneDX SBOMs (JSON format only) to current standard schema.

Next, we want to parse SPDX 2.2 using a dedicated schema parser with the goal of being able to losslessly convert it to the most current CycloneDX schema.

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

```go
go test github.com/mrutkows/sbom-utility/cmd -v
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
            "program": "main.go", // "program": "${file}",
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
