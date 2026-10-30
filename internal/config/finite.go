// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math"
	"reflect"
	"strings"
)

// validateFiniteNumbers checks the YAML-visible configuration independently of
// feature enablement. Walking the schema keeps future float fields covered.
func (c *Config) validateFiniteNumbers() error {
	return validateFiniteValue(reflect.ValueOf(c), "")
}

func validateFiniteValue(value reflect.Value, path string) error {
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !value.IsNil() {
			return validateFiniteValue(value.Elem(), path)
		}
	case reflect.Struct:
		typ := value.Type()
		for i := range value.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := strings.Split(field.Tag.Get("yaml"), ",")
			name := tag[0]
			if name == "-" {
				continue
			}
			inline := false
			for _, option := range tag[1:] {
				inline = inline || option == "inline"
			}
			fieldPath := path
			if !inline {
				if name == "" {
					name = strings.ToLower(field.Name)
				}
				if fieldPath != "" {
					fieldPath += "."
				}
				fieldPath += name
			}
			if err := validateFiniteValue(value.Field(i), fieldPath); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range value.Len() {
			if err := validateFiniteValue(value.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := value.MapRange()
		for iter.Next() {
			key := iter.Key()
			label := fmt.Sprint(key.Interface())
			if key.Kind() == reflect.String {
				label = fmt.Sprintf("%q", key.String())
			}
			entryPath := fmt.Sprintf("%s[%s]", path, label)
			if err := validateFiniteValue(key, entryPath); err != nil {
				return err
			}
			if err := validateFiniteValue(iter.Value(), entryPath); err != nil {
				return err
			}
		}
	case reflect.Float32, reflect.Float64:
		if number := value.Float(); math.IsNaN(number) || math.IsInf(number, 0) {
			return fmt.Errorf("%s must be a finite number", path)
		}
	}
	return nil
}
