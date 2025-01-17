package commands

import (

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var list = []commandInstanciator{newRun, newServer}

type (
	command interface {
		Info() string
		GetArgs() cobra.PositionalArgs
		GetDescription() string
		GetLongDescription() string
		GetRequiredFlags() []string
		Run() RunCmd
		SetFlags(*pflag.FlagSet)
	}
	commandInstanciator func() command
	RunCmd              func(cmd *cobra.Command, args []string)
)

func Prepare(root *cobra.Command) {
	for _, item := range list {
		var cobraCmd cobra.Command
		
		instance := item()

		cobraCmd.Use = instance.Info()
		cobraCmd.Short = instance.GetDescription()
		cobraCmd.Long = instance.GetLongDescription()
		cobraCmd.Args = instance.GetArgs()
		cobraCmd.Run = instance.Run()

		instance.SetFlags(cobraCmd.Flags())

		for _, f := range instance.GetRequiredFlags() {
			_ = cobraCmd.MarkFlagRequired(f)
		}

		root.AddCommand(&cobraCmd)
	}
}
