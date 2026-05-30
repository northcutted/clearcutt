package output

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// TablePrinter holds headers and rows for console alignment.
type TablePrinter struct {
	Headers []string
	Rows    [][]string
}

// NewTablePrinter creates an empty printer.
func NewTablePrinter(headers ...string) *TablePrinter {
	return &TablePrinter{
		Headers: headers,
		Rows:    [][]string{},
	}
}

// AddRow adds a data row.
func (tp *TablePrinter) AddRow(row ...string) {
	tp.Rows = append(tp.Rows, row)
}

// Print writes aligned tab-spaced columns to the writer.
func (tp *TablePrinter) Print(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)

	// Print headers
	for i, h := range tp.Headers {
		fmt.Fprint(tw, h)
		if i < len(tp.Headers)-1 {
			fmt.Fprint(tw, "\t")
		}
	}
	fmt.Fprintln(tw)

	// Print rows
	for _, row := range tp.Rows {
		for i, val := range row {
			fmt.Fprint(tw, val)
			if i < len(row)-1 {
				fmt.Fprint(tw, "\t")
			}
		}
		fmt.Fprintln(tw)
	}

	return tw.Flush()
}
