package config

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"
)

// Decoder decodes data from a Reader.
type Decoder struct {
	r io.Reader
}

// NewDecoder constructs a decoder from a Reader.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r}
}

// Decode builds config from the Reader data.
func (d *Decoder) Decode(v interface{}) error {
	data, err := ioutil.ReadAll(d.r)
	if err != nil {
		return err
	}

	return Unmarshal(data, v)
}

// Unmarshal config data into v.
func Unmarshal(data []byte, v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return errors.New("cannot unmarshal into nil or non pointer type")
	}
	rv = rv.Elem()

	sections, err := parse(data)
	if err != nil {
		return err
	}

	rootSection := sections[0]
	fields := getStructFieldsMap(rv.Type())

	if err := unmarshal(rootSection, rv, fields); err != nil {
		return err
	}

	for _, section := range sections[1:] {
		if unmarshalInto(section, rv, fields); err != nil {
			return err
		}
	}

	return nil
}

func unmarshal(section *section, rv reflect.Value, fields map[string]structField) error {
	visited := map[string]struct{}{}
	for key, values := range section.Values {
		field, ok := fields[key]
		if !ok {
			return fmt.Errorf("unknown config %q", key)
		}

		subv := rv.FieldByName(field.Name)
		if err := store(subv, values, key); err != nil {
			return err
		}
		visited[key] = struct{}{}
	}

	for _, field := range fields {
		if _, ok := visited[field.key]; !ok && !field.optional && !field.section {
			return fmt.Errorf("missing required config %q", field.key)
		}
	}
	return nil
}

func unmarshalInto(section *section, rv reflect.Value, fields map[string]structField) error {
	field, ok := fields[section.Type]
	if !ok {
		return fmt.Errorf("missing field for section type %q", section.Type)
	}
	if !field.section {
		return fmt.Errorf("invalid section type %q for field", section.Type)
	}

	subv := rv.FieldByName(field.Name)

	switch subv.Kind() {
	case reflect.Map:
		t := subv.Type()
		if t.Key().Kind() != reflect.String {
			return fmt.Errorf("invalid key type %s for section map field", t.Name())
		}
		if subv.IsNil() {
			subv.Set(reflect.MakeMap(t))
		}

		id := section.ID
		if id == "" {
			id = section.Type
		}

		kv := reflect.ValueOf(id)
		et := subv.Type().Elem()
		ev := reflect.New(et).Elem()

		if err := unmarshal(section, ev, getStructFieldsMap(et)); err != nil {
			return err
		}
		subv.SetMapIndex(kv, ev)
	}

	return nil
}

func store(v reflect.Value, values []string, key string) error {
	switch v.Kind() {
	case reflect.String:
		if len(values) > 1 {
			return fmt.Errorf("config %q has %d values, expected 1", key, len(values))
		}

		v.SetString(values[0])
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(values[0], 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(n)
	case reflect.Slice:
		et := v.Type().Elem()
		s := reflect.MakeSlice(v.Type(), 0, len(values))
		for _, val := range values {
			ev := reflect.New(et).Elem()
			if err := store(ev, []string{val}, key); err != nil {
				return err
			}
			s = reflect.Append(s, ev)
		}
		v.Set(s)
	default:
		panic(fmt.Sprintf("cannot unmarshal type %q", v.Kind()))
	}
	return nil
}

func getStructFieldsMap(typ reflect.Type) map[string]structField {
	fields := make(map[string]structField)
	for i := 0; i < typ.NumField(); i++ {
		field := structField{
			StructField: typ.Field(i),
		}

		if tag := field.Tag.Get("vcrypt"); tag != "" {
			for i, part := range strings.Split(tag, ",") {
				switch {
				case i == 0:
					field.key = part
				case part == "optional":
					field.optional = true
				case part == "section":
					field.section = true
				}
			}
			fields[field.key] = field
		}
	}
	return fields
}

type structField struct {
	reflect.StructField

	key string

	optional, section bool
}
