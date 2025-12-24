package utils

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

// Traverse traverse a 'MapSlice'
func Traverse(
	inp []yaml.MapItem,
	action func(string) (string, error),
) (
	out []yaml.MapItem,
	err error,
) {
	var nxt []yaml.MapItem
	out = make([]yaml.MapItem, 0)
	for _, itm := range inp {
		nxt, err = _traverse(itm.Key.(string), itm.Value, action)
		if err != nil {
			break
		}
		out = append(out, nxt...)
	}
	return
}

func _traverse(
	key string,
	ifc interface{},
	action func(string) (string, error),
) (
	out []yaml.MapItem,
	err error,
) {
	var enc string
	switch typ := ifc.(type) {
	case []yaml.MapItem:
		nxt, err := Traverse(typ, action)
		if err != nil {
			return nil, err
		}
		out = append(out, yaml.MapItem{Key: key, Value: nxt})
	case []interface{}:
		nxt := make([]interface{}, len(typ))
		out = append(out, yaml.MapItem{Key: key, Value: nxt})
		for i, f := range typ {
			err = __traverse(key, i, f, nxt, action)
			if err != nil {
				break
			}
		}
	case string:
		enc, err = action(typ)
		if err != nil {
			err = fmt.Errorf("[%v]%v", key, err)
		}
		out = append(out, yaml.MapItem{Key: key, Value: enc})
	default:
		out = append(out, yaml.MapItem{Key: key, Value: typ})
	}
	return
}

func __traverse(
	key string, idx int,
	ifc interface{},
	out []interface{},
	action func(string) (string, error),
) (err error) {
	switch typ := ifc.(type) {
	case []yaml.MapItem:
		nxt, err := Traverse(typ, action)
		if err != nil {
			return err
		}
		out[idx] = nxt
	case []interface{}:
		nxt := make([]interface{}, len(typ))
		out[idx] = nxt
		for i, f := range typ {
			err = __traverse(key, i, f, nxt, action)
			if err != nil {
				break
			}
		}
	case string:
		out[idx], err = action(typ)
		if err != nil {
			err = fmt.Errorf("[%v][%v]%v", key, idx, err)
		}
	default:
		out[idx] = typ
	}
	return
}
