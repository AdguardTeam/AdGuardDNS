package agdprotobuf

import "unsafe"

// UnsafelyConvertStrSlice checks if []T1 can be converted to []T2 at compile
// time and, if so, converts the slice using package unsafe.
//
// Slices resulting from this conversion must not be mutated.
// TODO(f.setrakov): Generalize.
func UnsafelyConvertStrSlice[T1, T2 ~string](s []T1) (res []T2) {
	if s == nil {
		return nil
	}

	// #nosec G103 -- Conversion between two slices with the same underlying
	// element type is safe.
	return *(*[]T2)(unsafe.Pointer(&s))
}

// UnsafelyConvertUint32Slice checks if []T1 can be converted to []T2 at compile
// time and, if so, converts the slice using package unsafe.
//
// Slices resulting from this conversion must not be mutated.
func UnsafelyConvertUint32Slice[T1, T2 ~uint32](s []T1) (res []T2) {
	if s == nil {
		return nil
	}

	// #nosec G103 -- Conversion between two slices with the same underlying
	// element type is safe.
	return *(*[]T2)(unsafe.Pointer(&s))
}
