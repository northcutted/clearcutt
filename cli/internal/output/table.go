package output

import (
	"fmt"
	"io"
	"strings"
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
	for _, row := range append([][]string{tp.Headers}, tp.Rows...) {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}
