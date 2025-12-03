package nav

import "fmt"

func Nav(
	inp, out map[string]interface{},
	convert func(string) (string, error),
) (err error) {
	for k, v := range inp {
		err = _nav(k, v, out, convert)
		if err != nil {
			break
		}
	}
	return
}

func _nav(
	key string,
	ifc interface{},
	out map[string]interface{},
	convert func(string) (string, error),
) (err error) {
	switch typ := ifc.(type) {
	case []interface{}:
		nxt := make([]interface{}, len(typ))
		out[key] = nxt
		for i, f := range typ {
			err = __nav(key, i, f, nxt, convert)
			if err != nil {
				break
			}
		}
	case map[string]interface{}:
		nxt := make(map[string]interface{})
		out[key] = nxt
		err = Nav(typ, nxt, convert)
	case string:
		out[key], err = convert(typ)
		if err != nil {
			err = fmt.Errorf("[%v]%v", key, err)
		}
	default:
		out[key] = typ
	}
	return
}

func __nav(
	key string, idx int,
	ifc interface{},
	out []interface{},
	convert func(string) (string, error),
) (err error) {
	switch typ := ifc.(type) {
	case []interface{}:
		nxt := make([]interface{}, len(typ))
		out[idx] = nxt
		for i, f := range typ {
			err = __nav(key, i, f, nxt, convert)
			if err != nil {
				break
			}
		}
	case map[string]interface{}:
		nxt := make(map[string]interface{})
		out[idx] = nxt
		err = Nav(typ, nxt, convert)
	case string:
		out[idx], err = convert(typ)
		if err != nil {
			err = fmt.Errorf("[%v][%v]%v", key, idx, err)
		}
	default:
		out[idx] = typ
	}
	return
}
