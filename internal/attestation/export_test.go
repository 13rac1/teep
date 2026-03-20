package attestation

func overrideSigstoreBase(base string) { sigstoreSearchBase = base }
func restoreSigstoreBase(base string)  { sigstoreSearchBase = base }
