package common

import (
	"errors"
	"hash/fnv"
	"reflect"
)

// Fowler–Noll–Vo is a non-cryptographic hash function created by Glenn Fowler, Landon Curt Noll, and Kiem-Phong Vo.
//The basis of the FNV hash algorithm was taken from an idea sent as reviewer comments to the
//IEEE POSIX P1003.2 committee by Glenn Fowler and Phong Vo in 1991. In a subsequent ballot round,
//Landon Curt Noll improved on their algorithm. In an email message to Landon,
//they named it the Fowler/Noll/Vo or FNV hash.
// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
func Fnv_hash_to_byte(data ...[]byte) []byte {
	d := fnv.New32()
	for _, b := range data {
		d.Write(b)
	}

	return d.Sum(nil)
	// return hex.EncodeToString(d.Sum(nil))
}

// 判断obj是否在target中，target支持的类型arrary,slice,map
func Contains(obj interface{}, target interface{}) (bool, error) {
	targetValue := reflect.ValueOf(target)
	switch reflect.TypeOf(target).Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < targetValue.Len(); i++ {
			if targetValue.Index(i).Interface() == obj {
				return true, nil
			}
		}
	case reflect.Map:
		if targetValue.MapIndex(reflect.ValueOf(obj)).IsValid() {
			return true, nil
		}
	}
	return false, errors.New("not in array")
}
