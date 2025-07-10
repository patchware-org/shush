package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	// Add the completion command to the root
	rootCmd.AddCommand(completionCmd)
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate autocompletion script for your shell",
	Long: `To load completions:

Bash:

  $ source <(shush completion bash)
  # To load completions for each session, add to your ~/.bashrc:
  #   source <(shush completion bash)

Zsh:

  $ shush completion zsh > "${fpath[1]}/_shush"
  # Or:
  $ shush completion zsh > ~/.zsh/completion/_shush

Fish:

  $ shush completion fish | source
  # To load automatically:
  $ shush completion fish > ~/.config/fish/completions/shush.fish

PowerShell:

  PS> shush completion powershell | Out-String | Invoke-Expression
  # To load for every session, add the above to your $PROFILE
`,
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
	Hidden:    true,
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		default:
			fmt.Fprintf(os.Stderr, "Unsupported shell type: %s\n", args[0])
		}
	},
}
