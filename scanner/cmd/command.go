package cmd

import "errors"

var ErrPrintHelp = errors.New("print help")

type ScannerCommand interface {
	Run() error
}
