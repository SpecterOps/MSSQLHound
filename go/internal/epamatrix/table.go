package epamatrix

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// PrintResultsTable writes a formatted ASCII table of matrix results.
func PrintResultsTable(w io.Writer, results []MatrixResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintf(tw, "#\tForce Encryption\tForce Strict Encryption\tExtended Protection\tDetected EPA\tVerdict\n")
	fmt.Fprintf(tw, "-\t----------------\t-----------------------\t-------------------\t------------\t-------\n")
	for _, r := range results {
		detected := "N/A"
		if r.EPAResult != nil {
			detected = r.EPAResult.EPAStatus
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n",
			r.Index,
			intToYesNo(r.ForceEncryption),
			intToYesNo(r.ForceStrictEncryption),
			epIntToLabel(r.ExtendedProtection),
			detected,
			r.Verdict,
		)
	}
	tw.Flush()
}

// Summarize prints a summary line of correct/incorrect/error counts.
func Summarize(w io.Writer, results []MatrixResult) {
	correct, incorrect, errors := 0, 0, 0
	for _, r := range results {
		switch {
		case r.Error != nil:
			errors++
		case strings.HasPrefix(r.Verdict, "Correct"):
			correct++
		default:
			incorrect++
		}
	}
	fmt.Fprintf(w, "\nSummary: %d correct, %d incorrect, %d errors out of %d tested\n",
		correct, incorrect, errors, len(results))
}

func intToYesNo(v int) string {
	if v == 1 {
		return "Yes"
	}
	return "No"
}

func epIntToLabel(v int) string {
	switch v {
	case 0:
		return "Off"
	case 1:
		return "Allowed"
	case 2:
		return "Required"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}
