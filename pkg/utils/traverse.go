package utils

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

// Traverse traverse a 'MapSlice'
func Traverse(
	inp []yaml.MapItem,
	action func(interface{}) (interface{}, error),
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
	action func(interface{}) (interface{}, error),
) (
	out []yaml.MapItem,
	err error,
) {
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
	default:
		var act interface{}
		act, err = action(typ)
		if err != nil {
			err = fmt.Errorf("[%v]%v", key, err)
		} else {
			out = append(out, yaml.MapItem{Key: key, Value: act})
		}
	}
	return
}

func __traverse(
	key string, idx int,
	ifc interface{},
	out []interface{},
	action func(interface{}) (interface{}, error),
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
	default:
		out[idx], err = action(typ)
		if err != nil {
			err = fmt.Errorf("[%v][%v]%v", key, idx, err)
		}
	}
	return
}
