package alterations

/*
import (
	"testing"
)

func checkAlterations(generated []string, expected []string) bool {
	return len(generated) == len(expected)
}

func createState() *State {
	altState := NewState([]string{"test", "abc", "123"})

	altState.MinForWordFlip = 3
	altState.EditDistance = 2

	return altState
}

func TestAlterations(t *testing.T) {
	fake := "fa2ke.owasp.org"
	altState := createState()

	t.Run("Fuzzy Label subtest", func(t *testing.T) {
		expected := []string{
			"uzyxw.owasp.org",
			"m-1e.owasp.org",
			"0ihgf.owasp.org",
		}

		fuzzyLabel := altState.FuzzyLabelSearches(fake)
		if !checkAlterations(fuzzyLabel, expected) {
			t.Errorf("Could not generate all fuzzy label alterations")
		}
	})

	t.Run("flip number label subtest", func(t *testing.T) {
		expected := []string{
			"fa0ke.owasp.org",
		}

		flipNumbers := altState.FlipNumbers(fake)
		if !checkAlterations(flipNumbers, expected) {
			t.Errorf("Could not generate all Flip Number")
		}
	})

	t.Run("append number label subtest", func(t *testing.T) {
		var expected []string
		for i := 0; i < 10; i++ {
			expected = append(expected, "fa2ke"+strconv.Itoa(i)+".owasp.org")
		}

		appendNumbers := altState.AppendNumbers(fake)
		if !checkAlterations(appendNumbers, expected) {
			t.Errorf("Could not generate all append number label alterations")
		}
	})

	t.Run("flip word label subtest", func(t *testing.T) {
		expected := []string{}
		flipWords := altState.FlipWords(fake)

		if !checkAlterations(flipWords, expected) {
			t.Errorf("Could not generate all flip words label alterations")
		}
	})

	t.Run("suffix label subtest", func(t *testing.T) {
		expected := []string{}
		addSuffix := altState.AddSuffixWord(fake)

		if !checkAlterations(addSuffix, expected) {
			t.Errorf("Could not generate all add suffix label alterations")
		}
	})

	t.Run("prefix number label subtest", func(t *testing.T) {
		expected := []string{}
		addPrefix := altState.AddPrefixWord(fake)

		if !checkAlterations(addPrefix, expected) {
			t.Errorf("Could not generate all add prefix number label alterations")
		}
	})
}
*/
