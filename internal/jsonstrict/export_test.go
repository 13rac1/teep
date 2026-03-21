package jsonstrict

// ResetWarned clears the dedup map. Exported for tests only.
func ResetWarned() {
	warned.Range(func(key, _ any) bool {
		warned.Delete(key)
		return true
	})
}
