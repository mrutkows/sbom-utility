[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# sbom-utility

This utility is designed to be an API platform used initially to validate SPDX or CycloneDX SBOMs (JSON format only) against officially published and versioned JSON schemas for recognized SBOM formats.

Specifically, we want to parse standardized SBOM output from tooling, validate it using the declared schema format (e.g., SPDX, CycloneDX) and version (e.g., "2.2", "1.3", etc.) with the goal of being able to losslessly convert it to the most current CycloneDX schema (normative) for comparison. Once this is accomplished we wish to support A "merge" command (with de-duplication if possible) of multiple CycloneDX SBOMs produced from a plurality of tool sources.

### Index

- [Installation](#installation)
- [Running](#running)
  - [Examples by command](#examples-by-command)
- [Development](#development)
  - [Prereqs](#prereqs)
  - [Building](#building)
  - [Running from source](#running-from-source)
  - [Supporting new SBOM formats and schema versions](#supporting-new-sbom-formats-and-schema-versions)
- [Testing](#testing)
  - [Authoring tests](#authoring-tests)
  - [Running tests](#running-tests)
  - [Tooling](#tooling)
- [References](#references)

---

### Installation

Since the utility comes with a default configuration file and input schemas ready-mde for both SPDX and CycloneDX validation, the best way to install it is to
clone the entirety of the repository at this time.   Over time, we hope to be able to create a release process for the binary with just the necessary supporting files, but at this time achieving the validation function is tactically important.

```bash
git clone git@github.com:mrutkows/sbom-utility.git
```
---

### Running

Currently, the utility supports the following commands:

- [help](#help)
- [schema](#schema)
- [validate](#validate)
- [query](#query)
- [list](#list)

### Quiet mode

By default, the utility outputs informational and processing text as well as any results of the command.  If you wish to only see the command results you can run any command in "quiet mode" by simply supplying the `-q` or `--quiet` flag.

```bash
$ ./sbom-utility validate -i examples/cyclonedx/juice-shop/bom.json -q
```

**Note**: commands such as `validate` return a numeric return code for use in automated processing where `0` indicates success and a non-zero value indicates failure of some kind designated by the number.

#### Examples by command

#### Help

The utility supports the `help` command for the root command as well as any supported commands

For example, to list top-level (root command) help which lists the supported "Available Commands":

```bash
$ ./sbom-utility help
```

A specific command-level help listing is also available. For example, you can access the help for the `validate` command:

```bash
$ ./sbom-utility validate help
```

#### Schema

You can verify which formats and schemas are available for validation by using the `schema` command:

```bash
$ go run main.go schema

Welcome to the sbom-utility! Version `x.y.z` (unset)
=====================================================

 format		 Schema		 Version
 ------		 ------		 -------
 SPDX		 SPDX-2.2
 SPDX		 SPDX-2.2	 development/v2.2.2
 CycloneDX	 1.2
 CycloneDX	 1.2		 strict
 CycloneDX	 1.3
 CycloneDX	 1.3		 strict
 CycloneDX	 1.3		 corporate
 CycloneDX	 1.4
 CycloneDX	 1.4		 strict
```

#### Validate

Validating the "juice shop" SBOM (CycloneDX 1.2) example provided in this repository using a "built" (i.e., `make build`) binary:

```bash
$ ./sbom-utility validate -i examples/cyclonedx/juice-shop/bom.json
```

##### Validating using schema variants

The validation command will use the declared format and version found within the SBOM JSON file itself to lookup the default (latest) matching schema version (as declared in`config.json`; however, if variants of that same schema (same format and version) are declared, they can be requested via the `--variant` command line flag:

```bash
$ ./sbom-utility validate -i test/cyclonedx/cdx-1-3-ibm-min-required.json --variant ibm
```

#### Query

This command allows you to perform SQL-like queries into JSON format SBOMs.  Currently, the command recognizes the `--select` and `--from` clauses.

```bash
$ ./sbom-utility query --select name,version --from component.metadata -i test/cyclonedx/cdx-1-3-min-required.json
```

**Note**: All results are returned as JSON documents.

---

### Development

#### Prereqs

- Go v1.16 or higher: see [https://go.dev/doc/install](https://go.dev/doc/install)
- `git` client: see [https://git-scm.com/downloads](https://git-scm.com/downloads)

#### Building

To produce a local binary named `sbom-utility` with version set to `latest` in the project root directory:

```bash
$ cd sbom-utility/
$ make build
```

to produce a release version you can set the following flags and invoke `go build` directly:
```bash
BINARY=sbom-utility
VERSION=latest
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Binary=${BINARY}"
$ go build ${LDFLAGS} -o ${BINARY}
```

**TODO**: Update the `Makefile` to add a `release` target that conditionally pulls these env. variable values and only uses the hardcoded values as defaults when not found in the runtime environment.

### Running from source

Developers can run using the current source code in their local branch using `go run main.go`. For example:

```bash
$ go run main.go validate -i examples/cyclonedx/package/npm/async/
```

### Supporting new SBOM formats and schema versions

The utility uses the [`config.json`](./config.json) file to lookup supported formats and their associated versioned schemas.  To add another SBOM format simply add another entry to the `format` array in the root of the document:

```json
{
            "canonicalName": "SPDX",
            "propertyKeyFormat": "SPDXID",
            "propertyKeyVersion": "spdxVersion",
            "propertyValueFormat": "SPDXRef-DOCUMENT",
            "schemas": [
                {
                   ...
                }
            ]
   ...
}
```

The value for `propertyKeyFormat` should be the exact name of key field that would appear in the JSON SBOM itself which can be used to confirm it is indeed a format match.  In addition, the corresponding value to match for that key should be declared in the `propertyValueFormat` value.

The fields `canonicalName`, `propertyKeyFormat`, `propertyKeyVersion`, and `propertyValueFormat` are required. The `format` object **MUST** have at least one valid `schema` object. The `schema` object appears as follows:

```json
{
     "version": "SPDX-2.2",
     "file": "file://schema/spdx/2.2.1/spdx-schema.json",
     "url": "https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json",
     "strict": false,
     "latest": true,
     "variant": ""
},
```

- Add a copy of the JSON schema file locally in the project under the structure `<format>/<spec>/<version>/schemas/<schema filename>`.
- Assure only one `schema` object entry has the value `latest` set to `true`.  This latest schema will be used when the SBOM being validated does not have a clear version declared <or> used with the `--force latest` flag (TODO).
- If you have a customized or "variant" version of a schema (with the same format and version values) you wish to use for validation (e.g., an `ibm` version with added requirements or test an unrelased version), you can create an entry that has the same `vesion` as another entry, but also declare its `variant` name _(non-empty value)_.  This value can be supplied on the commend line with the `--variant <variant name>` flag to force the validator to use it instead of the default _(empty variant value)_.

##### TODO list

- Using remote (network hosted) schema files for valdiation via the `url` field is supported in the configuration file; however, code is needed to implement the load/read/parse.

---

## Testing

### Authoring tests

As the actual tests files, `config.json` as well as the schema definition files are loaded relative to the project root, you will need to assure you change the working directory when initializing any `_test.go` module. For example, in `cmd/validate_test.go` file, you would need to change the working directory one level back:

```go
wd, _ := os.Getwd()
last := strings.LastIndex(wd, "/")
os.Chdir(wd[:last])
```

The "cmd" package already has a ready-made method named `initTestInfra()` in the `test.go` module that can be called during test module initialize to assure the proper working directory is setup to read any path-relative input files used by `go test` methods:

```go
func init() {
  initTestInfra()
}
```

### Running tests

Example: running test on the `cmd` package:

```sh
go test github.com/scs/sbom-utility/cmd -v
```

run an individual test within the `cmd` package:

```sh
go test github.com/scs/sbom-utility/cmd -v -run TestCDX13MinRequiredVariantIBM
```

#### Debugging go tests

Simply append the flags `--args -trace` to your `go test` command to enable trace output for your designated test(s).

```sh
go test github.com/scs/sbom-utility/cmd -v --args -trace
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

---

## References

### CycloneDX

- [CycloneDX Specification Overview](https://cyclonedx.org/specification/overview/)
- Specification (all versions): https://github.com/CycloneDX/specification
  - (JSON) Schemas: https://github.com/CycloneDX/specification/tree/master/schema
  - Examples: https://github.com/CycloneDX/sbom-examples

#### CycloneDX use cases

- [CycloneDX Use Cases](https://cyclonedx.org/use-cases/) (comprehensive)
  - [Inventory](https://cyclonedx.org/use-cases/#inventory) (PoC)
  - [License Compliance](https://cyclonedx.org/use-cases/#license-compliance) (PoC)
  - [Known Vulnerabilities](https://cyclonedx.org/use-cases/#known-vulnerabilities) (PoC)
- CycloneDX 1.4 Vulnerability Exploitability Exchange (VEX) BOM format
  - Overview: [https://cyclonedx.org/capabilities/vex/](https://cyclonedx.org/capabilities/vex/)
  - VEX examples: [https://github.com/CycloneDX/bom-examples/tree/master/VEX](https://github.com/CycloneDX/bom-examples/tree/master/VEX)

### SPDX

- GitHub: https://github.com/spdx
  - Specification: https://github.com/spdx/spdx-spec
  - Schemas: https://github.com/spdx/spdx-spec/tree/development/v2.2.2/schemas
- https://tools.spdx.org/app/convert/ - Used this to convert from tv format to json
  - NOTE: tool could not convert `example6-bin.spdx`; resulted in an error

### Software-Bill-of-Materials (SBOM)

- [Software Bill Of Materials: Formats, Use Cases, and Tools](https://fossa.com/blog/software-bill-of-materials-formats-use-cases-tools/)
- [NTIA - SBOM Minimum Requirements](https://www.ntia.doc.gov/blog/2021/ntia-releases-minimum-elements-software-bill-materials)
