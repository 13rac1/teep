package attestation

func overrideSigstoreBase(base string) { sigstoreSearchBase = base }
func restoreSigstoreBase(base string)  { sigstoreSearchBase = base }

func overrideNRASURL(url string) { nrasAttestURL = url }
func restoreNRASURL(url string)  { nrasAttestURL = url }

func overrideJWKSURL(url string) { nvidiaJWKSURL = url }
func restoreJWKSURL(url string)  { nvidiaJWKSURL = url }
