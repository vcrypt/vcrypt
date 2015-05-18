package cryptex

func nonNilLen(s [][]byte) int {
	count := 0
	for i := range s {
		if s[i] != nil {
			count++
		}
	}
	return count
}
