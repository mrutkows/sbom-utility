package cmd

import (
	"fmt"

	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
)

func init() {
	loggers.Enter()
	rootCmd.AddCommand(versionCmd)
	loggers.Exit()
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "display program, binary and version information",
	Long:  "display program, binary and version information in the form: `<project> version <x.y.z>`",
	Run: func(cmd *cobra.Command, args []string) {
		loggers.Enter()
		loggers.Info(fmt.Sprintf("%s version %s\n", utils.Flags.Project, utils.Flags.Version))
		loggers.Enter()
	},
}
