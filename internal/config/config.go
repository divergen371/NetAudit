package config

import "time"

type Config struct {
	TargetIP    string
	StartPort   int
	EndPort     int
	ScanType    string
	Protocol    string
	ScanSpeed   int
	Verbose     bool
	IfaceName   string
	Timeout     time.Duration
	WorkerCount int64
}
