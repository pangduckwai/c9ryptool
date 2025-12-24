package main

import (
	"fmt"

	"gopkg.in/yaml.v2"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func yamlTest() (err error) {
	input, err := utils.Read("test/test2.yaml", 65535, true)
	if err != nil {
		return
	}

	ms := make([]yaml.MapItem, 0)

	err = yaml.Unmarshal(input, &ms)
	if err != nil {
		return
	}

	out, err := Traverse(ms)
	if err != nil {
		return
	}

	output, err := yaml.Marshal(out)
	if err != nil {
		return
	}

	fmt.Printf("%s\n", output)
	return
}

func Traverse(
	in []yaml.MapItem,
) (
	out []yaml.MapItem,
	err error,
) {
	var nxt []yaml.MapItem
	out = make([]yaml.MapItem, 0)
	for _, itm := range in {
		if k, ok := itm.Key.(string); ok {
			nxt, err = _traverse(k, itm.Value)
			if err != nil {
				break
			}
			out = append(out, nxt...)
		}
	}
	return
}

func _traverse(
	key string,
	ifc interface{},
) (
	out []yaml.MapItem,
	err error,
) {
	out = make([]yaml.MapItem, 0)
	switch typ := ifc.(type) {
	case []yaml.MapItem:
		nxt, err := Traverse(typ)
		if err != nil {
			return nil, err
		}
		out = append(out, yaml.MapItem{Key: key, Value: nxt})
		fmt.Printf("TEMP0 %v: %v\n", key, len(nxt))
	case []interface{}:
		nxt := make([]interface{}, len(typ))
		out = append(out, yaml.MapItem{Key: key, Value: nxt})
		for i, f := range typ {
			err = __traverse(key, i, f, nxt)
			if err != nil {
				break
			}
		}
		fmt.Printf("TEMP1 %v: %v\n", key, len(nxt))
	case string:
		// fmt.Printf("TEMP -- %v: \"%v\"\n", key, typ)
		out = append(out, yaml.MapItem{Key: key, Value: typ}) // TODO TEMP!!!
	default:
		// fmt.Printf("TEMP -- %v: %v\n", key, typ)
		out = append(out, yaml.MapItem{Key: key, Value: typ})
	}
	return
}

func __traverse(
	key string,
	idx int,
	ifc interface{},
	out []interface{},
) (err error) {
	switch typ := ifc.(type) {
	case []yaml.MapItem:
		nxt, err := Traverse(typ)
		if err != nil {
			return err
		}
		out[idx] = nxt
		fmt.Printf("TEMP2 %v[%v]: %v\n", key, idx, len(nxt))
	case []interface{}:
		nxt := make([]interface{}, len(typ))
		out[idx] = nxt
		for i, f := range typ {
			err = __traverse(key, i, f, nxt)
			if err != nil {
				break
			}
		}
		fmt.Printf("TEMP3 %v[%v]: %v\n", key, idx, len(nxt))
	case string:
		// fmt.Printf("TEMP %2v %v: \"%v\"\n", idx, key, typ)
		out[idx] = typ // TODO TEMP!!!
	default:
		// fmt.Printf("TEMP %2v %v: %v\n", idx, key, typ)
		out[idx] = typ
	}
	return
}
