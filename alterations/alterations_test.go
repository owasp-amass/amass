package main

import (
	"github.com/OWASP/Amass/v3/alterations"
	"testing"
)

var subdomain = "fa2ke.owasp.org"

func checkAlterations(generated []string, expected []string) bool {
	return len(generated) == len(expected);
}

func createState() *alterations.State {
	Wordlist := []string{"test", "abc", "123"}
	altState := alterations.NewState(Wordlist)
	altState.MinForWordFlip = 3
	altState.EditDistance = 2
	return altState
}

func TestAlterations(t *testing.T) {
	domain := "www.owasp.org"
	altState := createState(wordlist)
	t.Run("Fuzzy Label subtest", func(t *testing.T) {
		expectedSubdomains := []string{
			"uzyxw.owasp.org",
			"m-1e.owasp.org",
			"0ihgf.owasp.org",
		}
		fuzzyLabel := altState.FuzzyLabelSearches(subdomain)
		if !checkAlterations(fuzzyLabel, expectedSubdomains) {
			t.Errorf("Could not generate all fuzzy label alterations")
		}
	})
	t.Run("flip number label subtest", func(t *testing.T) {
		expectedSubdomains := []string{
			"fa7ke.owasp.org",
			"fa8ke.owasp.org",
			"fa3ke.owasp.org",
		}
		flipNumbers := altState.FlipNumbers(subdomain)
		if !checkAlterations(flipNumbers, expectedSubdomains) {
			t.Errorf("Could not generate all Flip Number")
		}
	})
	t.Run("append number label subtest", func(t *testing.T) {
		expectedSubdomains := []string{
			"fa2ke2.owasp.org",
			"fa2ke3.owasp.org",
			"fa2ke4.owasp.org",
		}
		appendNumbers := altState.AppendNumbers(subdomain)
		if !checkAlterations(appendNumbers, expectedSubdomains) {
			t.Errorf("Could not generate all append number label alterations")
		}
	})
	t.Run("flip word label subtest", func(t *testing.T) {
		expectedSubdomains := []string{}
		flipWords := altState.FlipWords(subdomain)
		if !checkAlterations(flipWords, expectedSubdomains) {
			t.Errorf("Could not generate all flip words label alterations")
		}
	})
	t.Run("suffix label subtest", func(t *testing.T) {
		expectedSubdomains := []string{}
		addSuffix := altState.AddSuffixWord(subdomain)
		if !checkAlterations(addSuffix, expectedSubdomains) {
			t.Errorf("Could not generate all add suffix label alterations")
		}
	})
	t.Run("prefix number label subtest", func(t *testing.T) {
		expectedSubdomains := []string{}
		addPrefix := altState.AddPrefixWord(subdomain)
		if !checkAlterations(addPrefix, expectedSubdomains) {
			t.Errorf("Could not generate all add prefix number label alterations")
		}
	})
}
