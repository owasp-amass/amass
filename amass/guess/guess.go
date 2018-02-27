// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package guess

type Guesser interface {
	Train()
	NextGuess() (string, error)
	NumGuesses() int
	AddGoodWords([]string)
	AddBadWords([]string)
	GoodWords() []string
	BadWords() []string
	NumGood() int
	NumBad() int
	Tag() string
}
