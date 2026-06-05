package main

import (
	"os"

	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script for mssqlhound.

Bash
  To load completions in your current session:
    source <(mssqlhound completion bash)

  To enable completions for every session (Linux):
    mssqlhound completion bash > /etc/bash_completion.d/mssqlhound

  To enable completions for every session (macOS):
    mssqlhound completion bash > $(brew --prefix)/etc/bash_completion.d/mssqlhound

Zsh
  To load completions in your current session:
    source <(mssqlhound completion zsh)

  To enable completions for every session:
    mssqlhound completion zsh > "${fpath[1]}/_mssqlhound"

  If shell completion is not already enabled in your zsh configuration, add:
    echo "autoload -U compinit; compinit" >> ~/.zshrc

Fish
  To load completions in your current session:
    mssqlhound completion fish | source

  To enable completions for every session:
    mssqlhound completion fish > ~/.config/fish/completions/mssqlhound.fish

PowerShell
  To load completions in your current session:
    mssqlhound completion powershell | Out-String | Invoke-Expression

  To enable completions for every session, add the output to your profile:
    mssqlhound completion powershell >> $PROFILE

You will need to start a new shell for persistent completions to take effect.`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
	}
}
