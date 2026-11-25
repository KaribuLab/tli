//go:build !unix

package internal

// Native inline IO is disabled on these platforms until runtime validation.
func watchInlineResize(bump func()) (func(), func()) { return func() {}, func() {} }
