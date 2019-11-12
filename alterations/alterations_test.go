package main

import (
    "testing"
    // "fmt"
    "github.com/OWASP/Amass/v3/alterations"
)

var subdomain = "fa2ke.test.com"

func check_alterations(generated_subdomains []string, expected_subdomains []string) int {
    total_results := 0
    for _, label := range generated_subdomains {
        for _, results := range expected_subdomains {
            if results == label {
                total_results++
            }
        }
    }
    return total_results
}

func create_state() *alterations.State {
    Wordlist := []string{"test", "abc", "123"}
    altState := alterations.NewState(Wordlist)
    altState.MinForWordFlip = 3
    altState.EditDistance = 2
    return altState
}

func TestAddPrefixWord(t *testing.T) {
    expected_subdomains := []string{
    }
    altState := create_state()
    add_prefix := altState.AddPrefixWord(subdomain)
    num_generated := check_alterations(add_prefix, expected_subdomains)
    if num_generated  != len(expected_subdomains) {
        t.Errorf("Could not generate all add prefix number label alterations, generated %d/%d", num_generated, len(expected_subdomains))
    }
}

func TestAddSuffixWord(t *testing.T) {
    expected_subdomains := []string{
    }
    altState := create_state()
    add_suffix := altState.AddSuffixWord(subdomain)
    num_generated := check_alterations(add_suffix, expected_subdomains)
    if num_generated  != len(expected_subdomains) {
        t.Errorf("Could not generate all add suffix label alterations, generated %d/%d", num_generated, len(expected_subdomains))
    }
}

func TestFlipWords(t *testing.T) {
    expected_subdomains := []string{
    }
    altState := create_state()
    flip_words := altState.FlipWords(subdomain)
    num_generated := check_alterations(flip_words, expected_subdomains)
    if num_generated  != len(expected_subdomains) {
        t.Errorf("Could not generate all flip words label alterations, generated %d/%d", num_generated, len(expected_subdomains))
    }
} 

func TestAppendNumbers(t *testing.T) {
    expected_subdomains := []string{
        "fa2ke2.test.com", 
        "fa2ke3.test.com",
        "fa2ke4.test.com",
    }
    altState := create_state()
    append_numbers := altState.AppendNumbers(subdomain)
    num_generated := check_alterations(append_numbers, expected_subdomains)
    if num_generated  != len(expected_subdomains) {
        t.Errorf("Could not generate all append number label alterations, generated %d/%d", num_generated, len(expected_subdomains))
    }
}

func TestFlipNumbers(t *testing.T) {
    expected_subdomains := []string{
        "fa7ke.test.com", 
        "fa8ke.test.com",
        "fa3ke.test.com",
    }
    altState := create_state()
    flip_numbers := altState.FlipNumbers(subdomain)
    num_generated := check_alterations(flip_numbers, expected_subdomains)
    if num_generated  != len(expected_subdomains) {
        t.Errorf("Could not generate all flip number label alterations, generated %d/%d", num_generated, len(expected_subdomains))
    }
}

func TestFuzzyLabels(t *testing.T) {
    expected_subdomains := []string{
        "uzyxw.test.com",
        "m-1e.test.com",
        "0ihgf.test.com",
    }
    altState := create_state()
    fuzzy_label := altState.FuzzyLabelSearches(subdomain)
    num_generated := check_alterations(fuzzy_label, expected_subdomains)
    if num_generated  != len(expected_subdomains) {
        t.Errorf("Could not generate all fuzzy label alterations, generated %d/%d", num_generated, len(expected_subdomains))
    }
} 