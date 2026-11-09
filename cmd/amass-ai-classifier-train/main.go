// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "amass-ai-classifier-train:", err)
		os.Exit(1)
	}
}
func run() error {
	input := flag.String("input", "", "Labeled training examples in JSONL format")
	output := flag.String("output", "", "Output trained JSON model file")
	id := flag.String("model-id", "oam-organization-provenance-v1", "Model ID")
	flag.Parse()
	if *input == "" || *output == "" {
		return errors.New("-input and -output required")
	}
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	examples, err := classify.ReadLabeledJSONL(f)
	_ = f.Close()
	if err != nil {
		return err
	}
	model, metrics, err := classify.TrainLinearModel(examples, *id)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(*output)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".classifier-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), *output); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Classifier trained and saved:", *output)
	return json.NewEncoder(os.Stdout).Encode(metrics)
}
