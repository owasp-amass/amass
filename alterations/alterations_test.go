package main

import (
	"github.com/OWASP/Amass/v3/alterations"
	"testing"
)

var subdomain = "fa2ke.owasp.org"

func checkAlterations(generated []string, expected []string) bool {
	if len(generated) == len(expected) {
		return true
	} else {
		return false
	}
}

func create_state() *alterations.State {
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
		expected_subdomains := []string{
			"uzyxw.owasp.org",
			"m-1e.owasp.org",
			"0ihgf.owasp.org",
		}
		fuzzy_label := altState.FuzzyLabelSearches(subdomain)
		if !check_alterations(fuzzy_label, expected_subdomains) {
			t.Errorf("Could not generate all fuzzy label alterations")
		}
	})
	t.Run("flip number label subtest", func(t *testing.T) {
		expected_subdomains := []string{
			"fa7ke.owasp.org",
			"fa8ke.owasp.org",
			"fa3ke.owasp.org",
		}
		flip_numbers := altState.FlipNumbers(subdomain)
		if !check_alterations(flip_numbers, expected_subdomains) {
			t.Errorf("Could not generate all Flip Number")
		}
	})
	t.Run("append number label subtest", func(t *testing.T) {
		expected_subdomains := []string{
			"fa2ke2.owasp.org",
			"fa2ke3.owasp.org",
			"fa2ke4.owasp.org",
		}
		append_numbers := altState.AppendNumbers(subdomain)
		if !check_alterations(append_numbers, expected_subdomains) {
			t.Errorf("Could not generate all append number label alterations")
		}
	})
	t.Run("flip word label subtest", func(t *testing.T) {
		expected_subdomains := []string{}
		flip_words := altState.FlipWords(subdomain)
		if !check_alterations(flip_words, expected_subdomains) {
			t.Errorf("Could not generate all flip words label alterations")
		}
	})
	t.Run("suffix label subtest", func(t *testing.T) {
		expected_subdomains := []string{}
		add_suffix := altState.AddSuffixWord(subdomain)
		if !check_alterations(add_suffix, expected_subdomains) {
			t.Errorf("Could not generate all add suffix label alterations")
		}
	})
	t.Run("prefix number label subtest", func(t *testing.T) {
		expected_subdomains := []string{}
		add_prefix := altState.AddPrefixWord(subdomain)
		if !check_alterations(add_prefix, expected_subdomains) {
			t.Errorf("Could not generate all add prefix number label alterations")
		}
	})
}
