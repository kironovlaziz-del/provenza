//go:build !windows

package main

func runPlatform(configPath string) { runUntilSignal(configPath) }
