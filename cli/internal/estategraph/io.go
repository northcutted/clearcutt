package estategraph

import (
	"bytes"
	"encoding/json"
	"os"
)

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func unmarshalJSON(data []byte, value any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	return dec.Decode(value)
}
