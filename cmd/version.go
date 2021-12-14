package cmd

import (
	"fmt"

	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
)

func init() {
	ProjectLogger.Enter()
	rootCmd.AddCommand(versionCmd)
	ProjectLogger.Exit()
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "display program, binary and version information",
	Long:  "display program, binary and version information in SemVer format (e.g., `<project> version <x.y.z>`)",
	Run: func(cmd *cobra.Command, args []string) {
		ProjectLogger.Enter()
		// TODO: print cpu architecture of binary (e.g., go version go1.16.3 darwin/amd64)
		fmt.Printf("%s version %s\n", utils.Flags.Project, utils.Flags.Version)
		ProjectLogger.Enter()
	},
}
