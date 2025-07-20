package shared

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type JSONB map[string]any

// Value marshals JSONB into a database-friendly format.
func (j JSONB) Value() (driver.Value, error) {
	return json.Marshal(j)
}

// Scan unmarshals a database value into JSONB.
func (j *JSONB) Scan(value any) error {
	if value == nil {
		*j = make(JSONB)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into JSONB", value)
	}

	return json.Unmarshal(bytes, j)
}
